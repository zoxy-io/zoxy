//! Fixed pool of downstream connections and, for Phase-0 Step 3, an echo server
//! that exercises the full accept → recv → send → close lifecycle with zero
//! allocation on the serving path (docs/DESIGN.md §4). Everything is reserved at
//! startup; connection exhaustion rejects the new socket rather than allocating.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

const io_mod = @import("../io/io.zig");
const IO = io_mod.IO;
const Completion = io_mod.Completion;
const constants = @import("../constants.zig");
const Listener = @import("listener.zig").Listener;

/// One downstream connection. Owns its io_uring completions and read buffer
/// inline, so a submitted operation allocates nothing. Lives inside `Pool`.
pub const Connection = struct {
    io: *IO,
    pool: *Pool,
    fd: posix.socket_t,
    state: State,
    recv_completion: Completion,
    send_completion: Completion,
    close_completion: Completion,
    read_buf: [constants.read_buf_bytes]u8,
    /// Bytes currently being echoed back from `read_buf[sent..to_send]`.
    to_send: usize,
    sent: usize,
    /// Intrusive free-list link; non-null only while this slot is free.
    free_next: ?*Connection,

    pub const State = enum { idle, recving, sending, closing };

    /// Begin serving an accepted socket: echo bytes until the peer closes.
    pub fn start(conn: *Connection, io: *IO, pool: *Pool, fd: posix.socket_t) void {
        assert(fd >= 0);
        conn.io = io;
        conn.pool = pool;
        conn.fd = fd;
        conn.state = .idle;
        conn.to_send = 0;
        conn.sent = 0;
        conn.free_next = null;
        conn.armRecv();
    }

    fn armRecv(conn: *Connection) void {
        assert(conn.fd >= 0);
        conn.state = .recving;
        conn.io.recv(*Connection, conn, onRecv, &conn.recv_completion, conn.fd, &conn.read_buf);
    }

    fn onRecv(conn: *Connection, _: *Completion, result: io_mod.RecvError!usize) void {
        assert(conn.state == .recving);
        const n = result catch return conn.beginClose();
        if (n == 0) return conn.beginClose(); // peer half-closed / closed
        assert(n <= conn.read_buf.len);
        conn.to_send = n;
        conn.sent = 0;
        conn.armSend();
    }

    fn armSend(conn: *Connection) void {
        assert(conn.sent < conn.to_send);
        conn.state = .sending;
        conn.io.send(
            *Connection,
            conn,
            onSend,
            &conn.send_completion,
            conn.fd,
            conn.read_buf[conn.sent..conn.to_send],
        );
    }

    fn onSend(conn: *Connection, _: *Completion, result: io_mod.SendError!usize) void {
        assert(conn.state == .sending);
        const m = result catch return conn.beginClose();
        conn.sent += m;
        assert(conn.sent <= conn.to_send);
        if (conn.sent < conn.to_send) return conn.armSend(); // finish a partial write
        conn.armRecv(); // echo complete; read the next chunk
    }

    fn beginClose(conn: *Connection) void {
        assert(conn.fd >= 0);
        conn.state = .closing;
        conn.io.close(*Connection, conn, onClose, &conn.close_completion, conn.fd);
    }

    fn onClose(conn: *Connection, _: *Completion, result: io_mod.CloseError!void) void {
        assert(conn.state == .closing);
        result catch {}; // best-effort; the fd is gone regardless
        conn.fd = -1;
        conn.pool.release(conn);
    }
};

/// Fixed-capacity pool of `Connection`s backed by one startup allocation, with
/// an intrusive free list. Acquire/release never allocate.
pub const Pool = struct {
    connections: []Connection,
    free_head: ?*Connection,
    free_count: u32,
    capacity: u32,

    pub fn init(gpa: std.mem.Allocator, capacity: u32) !Pool {
        assert(capacity > 0);
        const connections = try gpa.alloc(Connection, capacity);
        var pool: Pool = .{
            .connections = connections,
            .free_head = null,
            .free_count = 0,
            .capacity = capacity,
        };
        // Build the free list so acquire() hands out slot 0 first.
        var i: u32 = capacity;
        while (i > 0) {
            i -= 1;
            pool.release(&connections[i]);
        }
        assert(pool.free_count == capacity);
        return pool;
    }

    pub fn deinit(pool: *Pool, gpa: std.mem.Allocator) void {
        gpa.free(pool.connections);
        pool.* = undefined;
    }

    /// Take a free connection, or null when exhausted (caller applies backpressure).
    pub fn acquire(pool: *Pool) ?*Connection {
        const conn = pool.free_head orelse return null;
        pool.free_head = conn.free_next;
        conn.free_next = null;
        assert(pool.free_count > 0);
        pool.free_count -= 1;
        return conn;
    }

    pub fn release(pool: *Pool, conn: *Connection) void {
        assert(pool.free_count < pool.capacity);
        conn.free_next = pool.free_head;
        pool.free_head = conn;
        pool.free_count += 1;
    }
};

/// Phase-0 echo server: accept loop over a `Listener`, one pooled `Connection`
/// per accepted socket. A placeholder for the proxy data path built in Step 7.
pub const EchoServer = struct {
    io: *IO,
    pool: *Pool,
    listener: Listener,
    accept_completion: Completion,

    pub fn init(io: *IO, pool: *Pool, listener: Listener) EchoServer {
        return .{ .io = io, .pool = pool, .listener = listener, .accept_completion = undefined };
    }

    pub fn start(server: *EchoServer) void {
        server.armAccept();
    }

    fn armAccept(server: *EchoServer) void {
        server.io.accept(*EchoServer, server, onAccept, &server.accept_completion, server.listener.fd);
    }

    fn onAccept(server: *EchoServer, _: *Completion, result: io_mod.AcceptError!posix.socket_t) void {
        if (result) |fd| {
            if (server.pool.acquire()) |conn| {
                conn.start(server.io, server.pool, fd);
            } else {
                _ = linux.close(fd); // backpressure: reject, never allocate
            }
        } else |_| {
            // Transient accept error; keep the listener armed.
        }
        server.armAccept();
    }
};

// ---- tests ----------------------------------------------------------------

fn connectLoopback(port: u16) !posix.socket_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try std.testing.expect(posix.errno(rc) == .SUCCESS);
    const fd: posix.socket_t = @intCast(rc);
    var sa: linux.sockaddr.in = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
    };
    try std.testing.expect(posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS);
    return fd;
}

test "echo: pooled connection echoes then releases on close" {
    const gpa = std.testing.allocator;
    const capacity: u32 = 4;

    var pool = try Pool.init(gpa, capacity);
    defer pool.deinit(gpa);

    var io = try IO.init(16, 0);
    defer io.deinit();

    var listener = try Listener.open(std.Io.net.Ip4Address.loopback(0), 8);
    defer listener.close();

    var server = EchoServer.init(&io, &pool, listener);
    server.start();

    const client = try connectLoopback(listener.boundAddress().port);

    const Client = struct {
        buf: [64]u8 = undefined,
        len: usize = 0,
        got_echo: bool = false,
        fn onSend(c: *@This(), _: *Completion, result: io_mod.SendError!usize) void {
            _ = c;
            _ = result catch unreachable;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch unreachable;
            c.got_echo = true;
        }
    };
    var c = Client{};
    var send_c: Completion = undefined;
    var recv_c: Completion = undefined;
    io.recv(*Client, &c, Client.onRecv, &recv_c, client, &c.buf);
    io.send(*Client, &c, Client.onSend, &send_c, client, "ping");

    try io.run_until_done(&c.got_echo);
    try std.testing.expectEqualStrings("ping", c.buf[0..c.len]);
    try std.testing.expectEqual(capacity - 1, pool.free_count);

    // Closing the client makes the connection observe EOF, close, and release.
    _ = linux.close(client);
    while (pool.free_count != capacity) try io.run_once();
    try std.testing.expectEqual(capacity, pool.free_count);
}
