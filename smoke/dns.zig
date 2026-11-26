//! The live gate's nameserver (#481): one name, answered over real UDP on
//! a loopback port, so the shipped binary's startup resolution and its
//! resolver on the loop both meet a real socket and a real kernel.
//!
//! Its own few lines of RFC 1035 rather than zoxy's codec: the harness
//! links nothing of the library, and an encoder written apart is what
//! makes a reply the resolver reads a check on its reader rather than an
//! agreement with itself. It answers A queries for `host` alone, with a
//! TTL of zero so every refresh asks again, and no record for any other
//! type; it asks nothing else, and is told nothing.
//!
//! The harness moves the name (`move`): from then on it answers with the
//! second address, and the gate watches the proxy follow.

const std = @import("std");

const Io = std.Io;

const assert = std.debug.assert;

/// The name the dns leg's cluster follows.
pub const host = "follow.zoxy.test";

/// `host` in wire form, as a query spells its question.
const host_wire = "\x06follow\x04zoxy\x04test\x00";

/// The datagram that wakes the task to stop: shorter than a header, so
/// it is never answered.
const wake_bytes = "stop";

const header_bytes = 12;
/// The question's name, type and class, as a reply echoes them.
const question_bytes = host_wire.len + 4;
const type_a: u16 = 1;
/// A reply: the header, the question, and one A record whose owner points
/// back at the question's name.
const reply_bytes_max = header_bytes + question_bytes + 16;

comptime {
    assert(host_wire.len == host.len + 2);
}

pub const Nameserver = struct {
    io: Io,
    socket: Io.net.Socket,
    /// The kernel-assigned port, read back after the bind.
    port: u16,
    /// The name's IPv4 address before `move` and after it.
    before: [4]u8,
    after: [4]u8,
    moved: std.atomic.Value(bool),
    stopping: std.atomic.Value(bool),
    /// Queries answered, for the leg's own failure text.
    answered: std.atomic.Value(u32),
    group: Io.Group,

    pub fn start(nameserver: *Nameserver, io: Io, before: [4]u8, after: [4]u8) !void {
        nameserver.io = io;
        nameserver.before = before;
        nameserver.after = after;
        nameserver.moved = .init(false);
        nameserver.stopping = .init(false);
        nameserver.answered = .init(0);
        nameserver.group = .init;
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        nameserver.socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        nameserver.port = nameserver.socket.address.getPort();
        assert(nameserver.port != 0);
        try nameserver.group.concurrent(io, serveTask, .{nameserver});
    }

    /// From now on the name answers with `after`.
    pub fn move(nameserver: *Nameserver) void {
        nameserver.moved.store(true, .release);
    }

    /// Stop answering and join the task: a datagram of its own wakes it
    /// from its receive, and it returns once it sees the flag.
    pub fn stop(nameserver: *Nameserver) void {
        nameserver.stopping.store(true, .release);
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(nameserver.port) };
        nameserver.socket.send(nameserver.io, &address, wake_bytes) catch {
            std.debug.print("smoke: the nameserver's wake never sent\n", .{});
        };
        nameserver.group.await(nameserver.io) catch {};
        nameserver.socket.close(nameserver.io);
    }
};

/// Receive, answer, repeat — until `stop`'s wake lands. Unbounded for the
/// one reason the origin's tasks are: the only way out is `stop`, which
/// sets the flag and sends the datagram this task wakes on.
fn serveTask(nameserver: *Nameserver) void {
    var buffer: [512]u8 = undefined;
    var reply_buffer: [reply_bytes_max]u8 = undefined;
    while (true) {
        const incoming = nameserver.socket.receive(nameserver.io, &buffer) catch return;
        if (nameserver.stopping.load(.acquire)) return;
        const address = if (nameserver.moved.load(.acquire)) nameserver.after else nameserver.before;
        const answered = answer(incoming.data, &address, &reply_buffer) orelse continue;
        nameserver.socket.send(nameserver.io, &incoming.from, answered) catch continue;
        _ = nameserver.answered.fetchAdd(1, .monotonic);
    }
}

/// The reply to `query`, or null when it is no query for `host`: an A
/// record of `address`, or no record for another type. zoxy's queries carry an EDNS0 record after
/// the question, which this reply does not echo — RFC 6891 lets a server
/// that does not speak EDNS0 answer without one.
fn answer(query: []const u8, address: *const [4]u8, buffer: *[reply_bytes_max]u8) ?[]const u8 {
    if (query.len < header_bytes) return null;
    // QR clear, and one question.
    if (query[2] & 0x80 != 0) return null;
    if (std.mem.readInt(u16, query[4..6], .big) != 1) return null;
    const question = query[header_bytes..];
    const known = question.len >= question_bytes and std.ascii.eqlIgnoreCase(question[0..host_wire.len], host_wire);
    if (!known) return null;
    const record_type = std.mem.readInt(u16, question[host_wire.len..][0..2], .big);
    const echoed = question[0..question_bytes];
    if (record_type != type_a) return reply(query[0..2], 0, echoed, buffer);
    return replyWithAddress(query[0..2], echoed, address, buffer);
}

/// A header and `question` echoed, no answer.
fn reply(id: *const [2]u8, rcode: u8, question: []const u8, buffer: *[reply_bytes_max]u8) []const u8 {
    assert(rcode <= 15);
    assert(question.len == question_bytes);
    @memcpy(buffer[0..2], id);
    buffer[2] = 0x81; // QR, RD
    buffer[3] = 0x80 | rcode; // RA
    std.mem.writeInt(u16, buffer[4..6], 1, .big);
    @memset(buffer[6..header_bytes], 0);
    @memcpy(buffer[header_bytes..][0..question.len], question);
    return buffer[0 .. header_bytes + question.len];
}

fn replyWithAddress(id: *const [2]u8, question: []const u8, address: *const [4]u8, buffer: *[reply_bytes_max]u8) []const u8 {
    assert(question.len == question_bytes);
    const head = reply(id, 0, question, buffer);
    std.mem.writeInt(u16, buffer[6..8], 1, .big); // one answer
    const record = buffer[head.len..][0..16];
    // The owner, a pointer to the question's name at the header's end;
    // type A, class IN, TTL 0, four octets of address.
    record.* = .{ 0xc0, header_bytes, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0 };
    @memcpy(record[12..16], address);
    return buffer[0 .. head.len + record.len];
}
