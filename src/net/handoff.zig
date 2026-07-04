//! Hot-restart listener handoff (docs/DESIGN.md §7 Phase 4). The old process
//! serves its per-worker `SO_REUSEPORT` listener fds over a unix socket; the
//! new process adopts them at startup. `SCM_RIGHTS` duplicates the fds, so
//! when the old workers later close their copies during the drain, the accept
//! queues survive in the new process — closing the drain-only RST window.
//!
//! Everything here is blocking syscalls, deliberately: the new side runs once
//! at startup, the old side on a dedicated thread (like the admin plane) —
//! never on the data path. Failure anywhere is graceful: the new process
//! falls back to fresh `SO_REUSEPORT` binds beside the old one.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

const constants = @import("../constants.zig");
const Metrics = @import("../obs/metrics.zig").Metrics;
const Counters = @import("../obs/metrics.zig").Counters;
const Ip4Address = std.Io.net.Ip4Address;

pub const fds_max = constants.workers_max;

/// Bounds the stats block a successor will read. Generous: every counter
/// record is a length-prefixed name plus a u64.
pub const stats_bytes_max: u32 = 16 * 1024;

const magic: u32 = 0x584f5a48; // "HZOX"
const version: u32 = 2;
const accept_backlog = 4;

/// Fixed-layout message head sent before the fd-carrying cmsg; lets the new
/// side refuse a stranger, a version skew, or a listener for the wrong
/// address without touching the fds. `stats_bytes` of counter records
/// follow the header on the same stream.
pub const Header = extern struct {
    magic: u32,
    version: u32,
    listener_count: u32,
    listen_address: [4]u8,
    listen_port: u16,
    reserved: u16 = 0,
    stats_bytes: u32,
};

comptime {
    assert(@sizeOf(Header) == 24); // no hidden padding crosses the wire
}

/// One SCM_RIGHTS cmsg big enough for every worker's listener.
/// Layout mirrors `tls/kernel.zig`'s RecordTypeControl: header, then data.
const FdControl = extern struct {
    header: linux.cmsghdr,
    fds: [fds_max]i32,
};

comptime {
    assert(@offsetOf(FdControl, "fds") == @sizeOf(linux.cmsghdr)); // CMSG_DATA
}

/// cmsg lengths: CMSG_LEN carries the header + payload, the buffer space is
/// that rounded up to cmsg alignment (sizeof(long)).
fn control_length(fd_count: usize) usize {
    assert(fd_count > 0);
    assert(fd_count <= fds_max);
    return @sizeOf(linux.cmsghdr) + fd_count * @sizeOf(i32);
}

fn control_space(fd_count: usize) usize {
    return std.mem.alignForward(usize, control_length(fd_count), @alignOf(linux.cmsghdr));
}

// ---- counter records --------------------------------------------------------
//
// Counters cross the restart as name-keyed records — `u8` name length, the
// name, a little-endian `u64` value — so a successor built from a different
// zoxy version simply ignores names it does not know and leaves absent ones
// at zero. Gauges (`Counters.gauge_fields`) and the diagnostic per-worker
// accept distribution deliberately start over.

/// Encode every transferable counter (its cross-shard total) into `buffer`;
/// returns bytes written.
pub fn snapshot_stats(metrics: *const Metrics, buffer: []u8) usize {
    assert(buffer.len >= stats_bytes_max);
    var offset: usize = 0;
    inline for (@typeInfo(Counters).@"struct".fields) |field| {
        if (comptime !Counters.is_gauge(field.name)) {
            comptime assert(field.name.len <= std.math.maxInt(u8));
            const record_length = 1 + field.name.len + @sizeOf(u64);
            assert(offset + record_length <= buffer.len); // sized by the comptime field set
            buffer[offset] = @intCast(field.name.len);
            offset += 1;
            @memcpy(buffer[offset..][0..field.name.len], field.name);
            offset += field.name.len;
            const value = metrics.total(field.name);
            std.mem.writeInt(u64, buffer[offset..][0..8], value, .little);
            offset += 8;
        }
    }
    assert(offset > 0); // Counters always has transferable fields
    assert(offset <= stats_bytes_max);
    return offset;
}

/// Fold received counter records into the dedicated adopted shard (its
/// counters start at zero, so `add` restores the predecessor's totals
/// without touching any worker's shard). Unknown names are skipped; a
/// malformed tail stops the fold — stats are best-effort by design, the
/// adopted listeners must never depend on them.
pub fn apply_stats(metrics: *Metrics, records: []const u8) void {
    const adopted = metrics.shard(Metrics.shard_adopted);
    var offset: usize = 0;
    var applied: u32 = 0;
    while (offset < records.len) {
        const name_length: usize = records[offset];
        offset += 1;
        if (name_length == 0) return; // malformed: stop, keep what was applied
        if (offset + name_length + @sizeOf(u64) > records.len) return;
        const name = records[offset..][0..name_length];
        offset += name_length;
        const value = std.mem.readInt(u64, records[offset..][0..8], .little);
        offset += 8;
        inline for (@typeInfo(Counters).@"struct".fields) |field| {
            if (comptime !Counters.is_gauge(field.name)) {
                if (std.mem.eql(u8, field.name, name)) @field(adopted, field.name).add(value);
            }
        }
        applied += 1;
        assert(applied <= stats_bytes_max / (1 + @sizeOf(u64))); // bounded by the wire format
    }
}

// ---- old side ---------------------------------------------------------------

/// Bind the handoff unix socket, replacing any stale file at `path` (a crash
/// leaves one behind; the successor owns the name). Called at startup.
pub fn open_server(path: []const u8) error{HandoffSocketFailed}!posix.socket_t {
    assert(path.len > 0);
    const fd = unix_socket() orelse return error.HandoffSocketFailed;
    var address = sockaddr_un(path) orelse return error.HandoffSocketFailed;
    _ = linux.unlink(@ptrCast(&address.path)); // stale file from a crash: ours now
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un))) != .SUCCESS) {
        _ = linux.close(fd);
        return error.HandoffSocketFailed;
    }
    if (linux.errno(linux.listen(fd, accept_backlog)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.HandoffSocketFailed;
    }
    return fd;
}

/// Block for one successor and hand it the listeners (and the counter
/// totals). True = a handoff happened and the caller must begin its own
/// drain. False = the client vanished or a send failed — serve the next one.
pub fn serve_once(
    server_fd: posix.socket_t,
    listeners: []const posix.socket_t,
    listen_address: Ip4Address,
    metrics: *const Metrics,
) bool {
    assert(listeners.len > 0);
    assert(listeners.len <= fds_max);
    const rc = linux.accept4(server_fd, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return false;
    const client: posix.socket_t = @intCast(rc);
    assert(client >= 0);
    defer _ = linux.close(client);
    return send_fds(client, listeners, listen_address, metrics);
}

/// The wire write: header + counter records in the iov, one SCM_RIGHTS
/// cmsg. Split from `serve_once` so the transfer is testable over a plain
/// socketpair.
pub fn send_fds(
    connection: posix.socket_t,
    listeners: []const posix.socket_t,
    listen_address: Ip4Address,
    metrics: *const Metrics,
) bool {
    assert(listeners.len > 0);
    assert(listeners.len <= fds_max);
    var stats_buffer: [stats_bytes_max]u8 = undefined;
    const stats_length = snapshot_stats(metrics, &stats_buffer);
    var header = Header{
        .magic = magic,
        .version = version,
        .listener_count = @intCast(listeners.len),
        .listen_address = listen_address.bytes,
        .listen_port = listen_address.port,
        .stats_bytes = @intCast(stats_length),
    };
    var control = FdControl{
        .header = .{
            .len = control_length(listeners.len),
            .level = linux.SOL.SOCKET,
            .type = linux.SCM.RIGHTS,
        },
        .fds = undefined,
    };
    for (listeners, control.fds[0..listeners.len]) |listener_fd, *slot| {
        assert(listener_fd >= 0);
        slot.* = listener_fd;
    }
    var segments = [2]posix.iovec_const{
        .{ .base = std.mem.asBytes(&header), .len = @sizeOf(Header) },
        .{ .base = &stats_buffer, .len = stats_length },
    };
    const message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &segments,
        .iovlen = segments.len,
        .control = &control,
        .controllen = @intCast(control_space(listeners.len)),
        .flags = 0,
    };
    const sent = linux.sendmsg(connection, &message, 0);
    if (linux.errno(sent) != .SUCCESS) return false;
    // A short write means a broken peer; the header alone decides validity
    // on the other side, and the stats tail is best-effort by design.
    return sent == @sizeOf(Header) + stats_length;
}

// ---- new side ---------------------------------------------------------------

/// Try to adopt listeners from a predecessor at `path`. Returns how many fds
/// were written into `fds_out`; 0 means no predecessor (first boot), a
/// protocol mismatch, or listeners for a different address — the caller
/// binds fresh in every one of those cases.
pub fn adopt(
    path: []const u8,
    listen_address: Ip4Address,
    fds_out: []posix.socket_t,
    metrics: ?*Metrics,
) usize {
    assert(path.len > 0);
    assert(fds_out.len > 0);
    const fd = unix_socket() orelse return 0;
    defer _ = linux.close(fd);
    var address = sockaddr_un(path) orelse return 0;
    const rc = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un));
    if (linux.errno(rc) != .SUCCESS) return 0; // first boot: nobody listening
    return recv_fds(fd, listen_address, fds_out, metrics);
}

/// The wire read: header + SCM_RIGHTS cmsg, then per-fd validation. Any
/// anomaly closes every received fd and returns 0 — adoption is
/// all-or-nothing and never trusts a stranger's descriptor.
pub fn recv_fds(
    connection: posix.socket_t,
    listen_address: Ip4Address,
    fds_out: []posix.socket_t,
    metrics: ?*Metrics,
) usize {
    assert(fds_out.len > 0);
    var header: Header = undefined;
    var control: FdControl = undefined;
    var segments = [1]posix.iovec{.{
        .base = std.mem.asBytes(&header),
        .len = @sizeOf(Header),
    }};
    var message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &segments,
        .iovlen = segments.len,
        .control = &control,
        .controllen = @sizeOf(FdControl),
        .flags = 0,
    };
    // WAITALL: the header must arrive whole (the cmsg rides its first byte);
    // the stats tail is read separately below.
    const flags = linux.MSG.CMSG_CLOEXEC | linux.MSG.WAITALL;
    const received = linux.recvmsg(connection, &message, flags);
    if (linux.errno(received) != .SUCCESS) return 0;
    if (received != @sizeOf(Header)) return 0; // EOF or a short/oversized head
    // Truncated control data means fds the kernel may have dropped — refuse.
    if (message.flags & linux.MSG.CTRUNC != 0) return 0;
    if (message.controllen < @sizeOf(linux.cmsghdr)) return 0; // no cmsg at all

    const cmsg_valid = control.header.level == linux.SOL.SOCKET and
        control.header.type == linux.SCM.RIGHTS and
        control.header.len > @sizeOf(linux.cmsghdr);
    const fd_count = if (cmsg_valid)
        (control.header.len - @sizeOf(linux.cmsghdr)) / @sizeOf(i32)
    else
        0;

    const announced_valid = header.magic == magic and
        header.version == version and
        header.listener_count > 0 and
        header.listener_count <= fds_max and
        header.listener_count == fd_count;
    const address_valid = std.mem.eql(u8, &header.listen_address, &listen_address.bytes) and
        header.listen_port == listen_address.port;
    if (!announced_valid or !address_valid or fd_count > fds_out.len) {
        // Refuse the batch; the fds are installed in our table regardless.
        for (control.fds[0..fd_count]) |received_fd| _ = linux.close(received_fd);
        return 0;
    }

    // Every adopted fd must be a listening socket bound to the configured
    // address — `getsockname` + SO_ACCEPTCONN, or the whole batch is refused.
    var valid = true;
    for (control.fds[0..fd_count]) |received_fd| {
        if (!is_listener_for(received_fd, listen_address)) valid = false;
    }
    if (!valid) {
        for (control.fds[0..fd_count]) |received_fd| _ = linux.close(received_fd);
        return 0;
    }
    for (control.fds[0..fd_count], fds_out[0..fd_count]) |received_fd, *slot| {
        slot.* = received_fd;
    }

    // The counter records ride behind the header. Best-effort: an absent,
    // oversized, or short block never un-adopts the listeners above.
    if (header.stats_bytes > 0 and header.stats_bytes <= stats_bytes_max) {
        var stats_buffer: [stats_bytes_max]u8 = undefined;
        var filled: usize = 0;
        while (filled < header.stats_bytes) { // bounded: every pass reads >= 1 byte or stops
            const stats_rc = linux.read(
                connection,
                stats_buffer[filled..].ptr,
                header.stats_bytes - filled,
            );
            if (linux.errno(stats_rc) != .SUCCESS) break;
            if (stats_rc == 0) break; // peer closed early: partial block
            filled += stats_rc;
            assert(filled <= header.stats_bytes);
        }
        if (metrics) |target| {
            if (filled == header.stats_bytes) apply_stats(target, stats_buffer[0..filled]);
        }
    }
    return fd_count;
}

fn is_listener_for(fd: posix.socket_t, listen_address: Ip4Address) bool {
    if (fd < 0) return false;
    var bound: linux.sockaddr.in = undefined;
    var bound_length: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &bound_length)) != .SUCCESS) {
        return false;
    }
    if (bound.family != linux.AF.INET) return false;
    const address_bytes: [4]u8 = @bitCast(bound.addr);
    if (!std.mem.eql(u8, &address_bytes, &listen_address.bytes)) return false;
    if (std.mem.bigToNative(u16, bound.port) != listen_address.port) return false;
    var accepting: c_int = 0;
    var option_length: posix.socklen_t = @sizeOf(c_int);
    const rc = linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.ACCEPTCONN,
        std.mem.asBytes(&accepting),
        &option_length,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    return accepting != 0;
}

// ---- shared helpers ---------------------------------------------------------

fn unix_socket() ?posix.socket_t {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

fn sockaddr_un(path: []const u8) ?linux.sockaddr.un {
    var address = linux.sockaddr.un{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= address.path.len) return null; // config.parse enforces this
    @memcpy(address.path[0..path.len], path);
    return address;
}

// ---- tests ------------------------------------------------------------------

const testing = std.testing;
const Listener = @import("listener.zig").Listener;

fn stream_socketpair() ![2]posix.socket_t {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    return .{ fds[0], fds[1] };
}

test "handoff: listener fds round-trip over SCM_RIGHTS and stay listeners" {
    var listener_a = try Listener.open(Ip4Address.loopback(0), 8);
    defer listener_a.close();
    const bound = listener_a.bound_address();
    var listener_b = try Listener.open(Ip4Address.loopback(bound.port), 8);
    defer listener_b.close();

    const pair = try stream_socketpair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    // Counters cross the restart (as cross-shard totals); gauges (`active`)
    // start over.
    var old_metrics = Metrics{};
    old_metrics.shard(0).accepted.add(40);
    old_metrics.shard(1).accepted.add(1);
    old_metrics.shard(0).requests.add(7);
    old_metrics.shard(0).bytes_to_client.add(123_456);
    old_metrics.shard(0).active.add(3);

    const sent = send_fds(pair[0], &.{ listener_a.fd, listener_b.fd }, bound, &old_metrics);
    try testing.expect(sent);

    var adopted: [fds_max]posix.socket_t = undefined;
    var new_metrics = Metrics{};
    const count = recv_fds(pair[1], bound, &adopted, &new_metrics);
    try testing.expectEqual(@as(usize, 2), count);
    for (adopted[0..count]) |fd| {
        try testing.expect(fd >= 0);
        try testing.expect(fd != listener_a.fd); // duplicated, not aliased
        try testing.expect(is_listener_for(fd, bound));
        _ = linux.close(fd);
    }
    try testing.expectEqual(@as(u64, 41), new_metrics.total("accepted"));
    try testing.expectEqual(@as(u64, 7), new_metrics.total("requests"));
    try testing.expectEqual(@as(u64, 123_456), new_metrics.total("bytes_to_client"));
    try testing.expectEqual(@as(u64, 0), new_metrics.total("active")); // gauge: reset
    // The fold lands in the adopted shard, never in a worker's.
    try testing.expectEqual(@as(u64, 41), new_metrics.shard(Metrics.shard_adopted).accepted.load());
    try testing.expectEqual(@as(u64, 0), new_metrics.shard(0).accepted.load());
}

test "handoff: unknown counter names are skipped, known ones still apply" {
    // A record stream from a *different* zoxy version: one counter this
    // build has never heard of, then one it knows.
    var records: [64]u8 = undefined;
    var offset: usize = 0;
    for ([_]struct { name: []const u8, value: u64 }{
        .{ .name = "counter_from_the_future", .value = 999 },
        .{ .name = "requests", .value = 17 },
    }) |record| {
        records[offset] = @intCast(record.name.len);
        offset += 1;
        @memcpy(records[offset..][0..record.name.len], record.name);
        offset += record.name.len;
        std.mem.writeInt(u64, records[offset..][0..8], record.value, .little);
        offset += 8;
    }

    var metrics = Metrics{};
    apply_stats(&metrics, records[0..offset]);
    try testing.expectEqual(@as(u64, 17), metrics.total("requests"));

    // A truncated tail stops the fold without touching anything else.
    var truncated = Metrics{};
    apply_stats(&truncated, records[0 .. offset - 3]);
    try testing.expectEqual(@as(u64, 0), truncated.total("requests"));
}

test "handoff: a queued connection survives the sender closing its copy" {
    var listener = try Listener.open(Ip4Address.loopback(0), 8);
    const bound = listener.bound_address();

    // A client lands in the accept queue before any handoff.
    const client: posix.socket_t = blk: {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        try testing.expect(linux.errno(rc) == .SUCCESS);
        break :blk @intCast(rc);
    };
    defer _ = linux.close(client);
    {
        var sa = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, bound.port),
            .addr = @bitCast(bound.bytes),
        };
        const rc = linux.connect(client, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
        try testing.expect(linux.errno(rc) == .SUCCESS);
    }

    const pair = try stream_socketpair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);
    var metrics = Metrics{};
    try testing.expect(send_fds(pair[0], &.{listener.fd}, bound, &metrics));
    var adopted: [fds_max]posix.socket_t = undefined;
    try testing.expectEqual(@as(usize, 1), recv_fds(pair[1], bound, &adopted, null));

    // The old process closes its copy — the drain path — and the queued
    // connection is still accepted through the adopted duplicate.
    listener.close();
    const accepted_rc = linux.accept4(adopted[0], null, null, linux.SOCK.CLOEXEC);
    try testing.expect(linux.errno(accepted_rc) == .SUCCESS);
    _ = linux.close(@as(posix.socket_t, @intCast(accepted_rc)));
    _ = linux.close(adopted[0]);
}

test "handoff: listeners for the wrong address are refused and closed" {
    var listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer listener.close();
    const bound = listener.bound_address();
    const elsewhere = Ip4Address.loopback(if (bound.port == 65535) 1 else bound.port + 1);

    const pair = try stream_socketpair();
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);
    var metrics = Metrics{};
    try testing.expect(send_fds(pair[0], &.{listener.fd}, bound, &metrics));
    var adopted: [fds_max]posix.socket_t = undefined;
    try testing.expectEqual(@as(usize, 0), recv_fds(pair[1], elsewhere, &adopted, null));
}

test "handoff: adopt without a predecessor returns zero (first boot)" {
    var adopted: [fds_max]posix.socket_t = undefined;
    const count = adopt(
        "/tmp/zoxy-handoff-test-nobody.sock",
        Ip4Address.loopback(80),
        &adopted,
        null,
    );
    try testing.expectEqual(@as(usize, 0), count);
}

test "handoff: full unix-socket path — serve_once hands off to adopt" {
    var listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer listener.close();
    const bound = listener.bound_address();

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/zoxy-handoff-test-{d}.sock", .{
        linux.getpid(),
    });
    const server_fd = try open_server(path);
    defer _ = linux.close(server_fd);

    var old_metrics = Metrics{};
    old_metrics.shard(0).requests.add(29);
    const Server = struct {
        fn run(
            fd: posix.socket_t,
            listener_fd: posix.socket_t,
            address: Ip4Address,
            metrics: *const Metrics,
        ) void {
            // One client, one handoff — mirrors the main-thread wiring.
            while (!serve_once(fd, &.{listener_fd}, address, metrics)) {}
        }
    };
    const thread = try std.Thread.spawn(
        .{},
        Server.run,
        .{ server_fd, listener.fd, bound, &old_metrics },
    );
    defer thread.join();

    var adopted: [fds_max]posix.socket_t = undefined;
    var new_metrics = Metrics{};
    const count = adopt(path, bound, &adopted, &new_metrics);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expect(is_listener_for(adopted[0], bound));
    try testing.expectEqual(@as(u64, 29), new_metrics.total("requests"));
    _ = linux.close(adopted[0]);

    var unlink_path = sockaddr_un(path).?;
    _ = linux.unlink(@ptrCast(&unlink_path.path));
}
