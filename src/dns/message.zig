//! DNS messages (RFC 1035 §4) as #481's resolver speaks them: a query for
//! one name's A or AAAA records, and the reply to it read back into
//! addresses. Sans-I/O and allocation-free, so the resolver on the loop
//! and the startup client share every byte of it.
//!
//! A reply is believed only as far as it proves itself: its ID, its one
//! question echoing the query's name, type and class, and an answer
//! section whose addresses are owned by the name asked — or by the end of
//! a CNAME chain that starts there. Records owned by anything else, and
//! the authority and additional sections, are never read, so a server
//! cannot steer a name through what it adds beside the answer.
//!
//! The responder's half — reading a query, writing a reply — is here for
//! the simulator's and the live gate's DNS servers, which then speak the
//! same wire format the resolver is held to.

const std = @import("std");

const constants = @import("../constants.zig");

const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;

/// The record types a query asks for.
pub const RecordType = enum(u16) {
    a = 1,
    aaaa = 28,

    pub fn addressBytes(record_type: RecordType) u16 {
        return switch (record_type) {
            .a => 4,
            .aaaa => 16,
        };
    }
};

const type_cname: u16 = 5;
const type_opt: u16 = 41;
const class_in: u16 = 1;
const header_bytes: u32 = 12;
/// A record's type, class, TTL and data length, after its owner.
const record_fixed_bytes: u32 = 10;
/// Recursion desired: the nameservers are recursive resolvers.
const flag_recursion_desired: u16 = 0x0100;
const flag_response: u16 = 0x8000;
const flag_truncated: u16 = 0x0200;

/// A name as dotted text, as `readName` writes one: a canonical host is at
/// most `dns_host_bytes_max`, and a longer name in a reply is refused.
const name_text_bytes_max = constants.dns_host_bytes_max;

pub const query_bytes_max = constants.dns_query_bytes_max;

/// What a reply said, once it proved itself the reply to the query.
pub const Outcome = enum {
    /// NOERROR: the addresses written, maybe none — the name then has no
    /// record of the type asked.
    answered,
    /// NXDOMAIN: no such name.
    nxdomain,
    /// The TC bit: the reply did not fit, and nothing of it is taken.
    truncated,
    /// SERVFAIL, REFUSED, or any other RCODE: another nameserver may know.
    failed,
};

pub const Reply = struct {
    outcome: Outcome,
    /// Addresses written to the caller's room.
    count: u16 = 0,
    /// Addresses past the room, not written.
    dropped: u16 = 0,
    /// The least TTL of the records the addresses came through, in
    /// seconds: the CNAMEs followed and the addresses themselves. Zero
    /// with no record.
    ttl_s: u32 = 0,
};

pub const ReadError = error{
    /// Not a DNS message that parses, or a reply to some other question.
    Malformed,
};

/// Write a query for the `record_type` records of `host` (canonical, as
/// `dns.host` gives it) under `id`, asking for recursion and advertising
/// `dns_message_bytes_max` in EDNS0.
pub fn writeQuery(buffer: *[query_bytes_max]u8, id: u16, host: []const u8, record_type: RecordType) []const u8 {
    assert(host.len >= 1);
    assert(host.len <= name_text_bytes_max);
    var writer: Writer = .{ .buffer = buffer };
    writer.header(id, flag_recursion_desired, 1, 0, 1);
    writer.name(host);
    writer.int(u16, @backingInt(record_type));
    writer.int(u16, class_in);
    // The OPT pseudo-record (RFC 6891 §6.1.2): the root's name, the UDP
    // payload this side takes in place of a class, no extended flags.
    writer.int(u8, 0);
    writer.int(u16, type_opt);
    writer.int(u16, constants.dns_message_bytes_max);
    writer.int(u32, 0);
    writer.int(u16, 0);
    assert(writer.length <= query_bytes_max);
    return buffer[0..writer.length];
}

/// The ID of `bytes` when it is a reply to a standard query — QR set and
/// the opcode QUERY — or null.
pub fn replyId(bytes: []const u8) ?u16 {
    if (bytes.len < header_bytes) return null;
    const flags = std.mem.readInt(u16, bytes[2..4], .big);
    if (flags & flag_response == 0) return null;
    const opcode = (flags >> 11) & 0xf;
    if (opcode != 0) return null;
    return std.mem.readInt(u16, bytes[0..2], .big);
}

/// Read `bytes` as the reply to the query (`id`, `host`, `record_type`):
/// its outcome, and on NOERROR the addresses `host` has, each with `port`,
/// into `addresses` — those past its room counted, not written.
pub fn readReply(
    bytes: []const u8,
    id: u16,
    host: []const u8,
    record_type: RecordType,
    port: u16,
    addresses: []IpAddress,
) ReadError!Reply {
    assert(host.len >= 1);
    assert(port != 0);
    if (replyId(bytes) != id) return error.Malformed;
    const flags = std.mem.readInt(u16, bytes[2..4], .big);
    const question_count = std.mem.readInt(u16, bytes[4..6], .big);
    const answer_count = std.mem.readInt(u16, bytes[6..8], .big);
    // Only a reply that echoes the question proves it answers it.
    if (question_count != 1) return error.Malformed;
    const answers = try readQuestion(bytes, host, record_type);
    if (flags & flag_truncated != 0) return .{ .outcome = .truncated };
    switch (flags & 0xf) {
        0 => {},
        3 => return .{ .outcome = .nxdomain },
        else => return .{ .outcome = .failed },
    }
    var target: Name = .{};
    target.set(host);
    var reply: Reply = .{ .outcome = .answered, .ttl_s = std.math.maxInt(u32) };
    const linked = try followCnames(bytes, answers, answer_count, &target, &reply.ttl_s);
    try collectAddresses(bytes, answers, answer_count, &target, record_type, port, addresses, &reply);
    if (reply.count == 0 and reply.dropped == 0) {
        // A chain that ends at no record is a server that did not finish
        // the work — a non-recursive one, or one that failed partway —
        // not a name with none: another nameserver may finish it.
        if (linked) return .{ .outcome = .failed };
        reply.ttl_s = 0;
    }
    assert(reply.count <= addresses.len);
    return reply;
}

/// Check the question section against the query's and return where the
/// answers begin.
fn readQuestion(bytes: []const u8, host: []const u8, record_type: RecordType) ReadError!u32 {
    assert(bytes.len >= header_bytes);
    var name: Name = .{};
    const after_name = try readName(bytes, header_bytes, &name);
    if (!name.equals(host)) return error.Malformed;
    if (after_name + 4 > bytes.len) return error.Malformed;
    const question_type = std.mem.readInt(u16, bytes[after_name..][0..2], .big);
    const question_class = std.mem.readInt(u16, bytes[after_name + 2 ..][0..2], .big);
    if (question_type != @backingInt(record_type)) return error.Malformed;
    if (question_class != class_in) return error.Malformed;
    return after_name + 4;
}

/// One answer record's place in the message.
const Record = struct {
    owner: Name,
    record_type: u16,
    class: u16,
    ttl_s: u32,
    data_offset: u32,
    data_length: u16,
    next: u32,
};

fn readRecord(bytes: []const u8, offset: u32) ReadError!Record {
    var record: Record = undefined;
    record.owner = .{};
    const after_owner = try readName(bytes, offset, &record.owner);
    if (after_owner + record_fixed_bytes > bytes.len) return error.Malformed;
    const fixed = bytes[after_owner..][0..record_fixed_bytes];
    record.record_type = std.mem.readInt(u16, fixed[0..2], .big);
    record.class = std.mem.readInt(u16, fixed[2..4], .big);
    const ttl_raw = std.mem.readInt(u32, fixed[4..8], .big);
    // A TTL with its top bit set is read as zero (RFC 2181 §8).
    record.ttl_s = if (ttl_raw > std.math.maxInt(i32)) 0 else ttl_raw;
    record.data_length = std.mem.readInt(u16, fixed[8..10], .big);
    record.data_offset = after_owner + record_fixed_bytes;
    record.next = record.data_offset + record.data_length;
    if (record.next > bytes.len) return error.Malformed;
    assert(record.next > offset);
    return record;
}

/// Move `target` along the answer's CNAME chain from the name asked, to
/// the name whose addresses the reply carries, and say whether it moved.
fn followCnames(bytes: []const u8, answers: u32, answer_count: u16, target: *Name, ttl_s: *u32) ReadError!bool {
    var links: u8 = 0;
    // Each pass follows one link or ends the chain.
    while (links <= constants.dns_cname_chain_max) : (links += 1) {
        var offset = answers;
        const link = for (0..answer_count) |_| {
            const record = try readRecord(bytes, offset);
            offset = record.next;
            if (record.record_type != type_cname or record.class != class_in) continue;
            if (record.owner.equals(target.text())) break record;
        } else return links != 0;
        var canonical: Name = .{};
        const end = try readName(bytes, link.data_offset, &canonical);
        if (end != link.next) return error.Malformed;
        target.* = canonical;
        ttl_s.* = @min(ttl_s.*, link.ttl_s);
    }
    // A chain past its bound: refused rather than followed further.
    return error.Malformed;
}

fn collectAddresses(
    bytes: []const u8,
    answers: u32,
    answer_count: u16,
    target: *const Name,
    record_type: RecordType,
    port: u16,
    addresses: []IpAddress,
    reply: *Reply,
) ReadError!void {
    assert(reply.count == 0);
    var offset = answers;
    for (0..answer_count) |_| {
        const record = try readRecord(bytes, offset);
        offset = record.next;
        if (record.record_type != @backingInt(record_type) or record.class != class_in) continue;
        if (!record.owner.equals(target.text())) continue;
        if (record.data_length != record_type.addressBytes()) return error.Malformed;
        reply.ttl_s = @min(reply.ttl_s, record.ttl_s);
        if (reply.count == addresses.len) {
            reply.dropped += 1;
            continue;
        }
        const data = bytes[record.data_offset..record.next];
        addresses[reply.count] = switch (record_type) {
            .a => .{ .ip4 = .{ .bytes = data[0..4].*, .port = port } },
            .aaaa => .{ .ip6 = .{ .bytes = data[0..16].*, .port = port } },
        };
        reply.count += 1;
    }
    assert(reply.count <= addresses.len);
}

/// A name as dotted, lowercased text.
const Name = struct {
    bytes: [name_text_bytes_max]u8 = undefined,
    length: u16 = 0,

    fn text(name: *const Name) []const u8 {
        assert(name.length <= name_text_bytes_max);
        return name.bytes[0..name.length];
    }

    fn set(name: *Name, host: []const u8) void {
        assert(host.len <= name_text_bytes_max);
        @memcpy(name.bytes[0..host.len], host);
        name.length = @intCast(host.len);
    }

    fn equals(name: *const Name, host: []const u8) bool {
        return std.mem.eql(u8, name.text(), host);
    }
};

/// Read the name at `offset` into `name`, following compression pointers
/// (RFC 1035 §4.1.4), and return the offset just past it where it is
/// spelled. Each pointer must point back, before the label it replaces,
/// so a name ends however its pointers are laid out. A label holding a
/// dot, a reserved label kind, or a name past 253 octets is refused.
fn readName(bytes: []const u8, offset: u32, name: *Name) ReadError!u32 {
    name.length = 0;
    var cursor = offset;
    var end: ?u32 = null;
    var steps: u32 = 0;
    // Every step moves the cursor forward through a label or back
    // through a pointer that points strictly earlier, so the count is
    // bounded by the message.
    while (steps <= bytes.len) : (steps += 1) {
        if (cursor >= bytes.len) return error.Malformed;
        const length = bytes[cursor];
        if (length == 0) {
            return end orelse cursor + 1;
        }
        switch (length & 0xc0) {
            0x00 => {
                const label_end = cursor + 1 + length;
                if (label_end > bytes.len) return error.Malformed;
                try appendLabel(name, bytes[cursor + 1 .. label_end]);
                cursor = label_end;
            },
            0xc0 => {
                if (cursor + 2 > bytes.len) return error.Malformed;
                const target = std.mem.readInt(u16, bytes[cursor..][0..2], .big) & 0x3fff;
                if (target >= cursor) return error.Malformed;
                if (end == null) end = cursor + 2;
                cursor = target;
            },
            else => return error.Malformed,
        }
    }
    return error.Malformed;
}

fn appendLabel(name: *Name, label: []const u8) ReadError!void {
    assert(label.len >= 1);
    assert(label.len <= 63);
    const separator: u16 = @intFromBool(name.length != 0);
    if (name.length + separator + label.len > name_text_bytes_max) return error.Malformed;
    if (separator == 1) {
        name.bytes[name.length] = '.';
        name.length += 1;
    }
    for (label) |byte| {
        if (byte == '.') return error.Malformed;
        name.bytes[name.length] = std.ascii.toLower(byte);
        name.length += 1;
    }
}

const Writer = struct {
    buffer: []u8,
    length: u32 = 0,

    fn int(writer: *Writer, comptime T: type, value: T) void {
        const size = @sizeOf(T);
        assert(writer.length + size <= writer.buffer.len);
        std.mem.writeInt(T, writer.buffer[writer.length..][0..size], value, .big);
        writer.length += size;
    }

    fn header(writer: *Writer, id: u16, flags: u16, questions: u16, answers: u16, additional: u16) void {
        assert(writer.length == 0);
        writer.int(u16, id);
        writer.int(u16, flags);
        writer.int(u16, questions);
        writer.int(u16, answers);
        writer.int(u16, 0);
        writer.int(u16, additional);
        assert(writer.length == header_bytes);
    }

    /// `host` in wire form: each label after its length, then the root.
    fn name(writer: *Writer, host: []const u8) void {
        assert(writer.length + host.len + 2 <= writer.buffer.len);
        var labels = std.mem.splitScalar(u8, host, '.');
        var count: u32 = 0;
        while (labels.next()) |label| : (count += 1) {
            assert(count < name_text_bytes_max);
            assert(label.len >= 1);
            assert(label.len <= 63);
            writer.int(u8, @intCast(label.len));
            @memcpy(writer.buffer[writer.length..][0..label.len], label);
            writer.length += @intCast(label.len);
        }
        writer.int(u8, 0);
    }

    fn bytes(writer: *Writer, data: []const u8) void {
        assert(writer.length + data.len <= writer.buffer.len);
        @memcpy(writer.buffer[writer.length..][0..data.len], data);
        writer.length += @intCast(data.len);
    }
};

/// A query as a responder reads it — the test DNS servers' half.
pub const Question = struct {
    id: u16,
    record_type: u16,
    host_bytes: [name_text_bytes_max]u8,
    host_length: u16,

    pub fn host(question: *const Question) []const u8 {
        return question.host_bytes[0..question.host_length];
    }
};

/// The question of query `bytes`, or null when it is no standard query
/// with one question.
pub fn readQuery(bytes: []const u8) ?Question {
    if (bytes.len < header_bytes) return null;
    const flags = std.mem.readInt(u16, bytes[2..4], .big);
    if (flags & flag_response != 0) return null;
    if (std.mem.readInt(u16, bytes[4..6], .big) != 1) return null;
    var name: Name = .{};
    const after_name = readName(bytes, header_bytes, &name) catch return null;
    if (after_name + 4 > bytes.len) return null;
    var question: Question = .{
        .id = std.mem.readInt(u16, bytes[0..2], .big),
        .record_type = std.mem.readInt(u16, bytes[after_name..][0..2], .big),
        .host_bytes = undefined,
        .host_length = name.length,
    };
    @memcpy(question.host_bytes[0..name.length], name.text());
    return question;
}

/// What a test DNS server answers.
pub const Answer = struct {
    /// The RCODE: 0, 2 (SERVFAIL), 3 (NXDOMAIN), 5 (REFUSED).
    rcode: u4 = 0,
    truncated: bool = false,
    /// A CNAME the question's name points to, whose addresses follow.
    cname: ?[]const u8 = null,
    addresses: []const IpAddress = &.{},
    ttl_s: u32 = 30,
    /// The ID the reply carries in place of the question's: a reply
    /// that does not belong.
    id: ?u16 = null,
};

/// Write the reply to `question` that `answer` describes: the question
/// echoed, then the CNAME if any, then each address of the question's
/// type. Into `buffer`, which must hold it.
pub fn writeReply(buffer: []u8, question: *const Question, answer: *const Answer) []const u8 {
    assert(question.host_length >= 1);
    assert(buffer.len >= header_bytes);
    var records: u16 = @intFromBool(answer.cname != null);
    for (answer.addresses) |*address| records += @intFromBool(addressFits(address, question.record_type));
    var flags: u16 = flag_response | flag_recursion_desired | 0x0080 | answer.rcode;
    if (answer.truncated) flags |= flag_truncated;
    var writer: Writer = .{ .buffer = buffer };
    writer.header(answer.id orelse question.id, flags, 1, records, 0);
    writer.name(question.host());
    writer.int(u16, question.record_type);
    writer.int(u16, class_in);
    var owner = question.host();
    if (answer.cname) |cname| {
        writeRecordHead(&writer, owner, type_cname, answer.ttl_s, @intCast(cname.len + 2));
        writer.name(cname);
        owner = cname;
    }
    for (answer.addresses) |*address| {
        if (!addressFits(address, question.record_type)) continue;
        switch (address.*) {
            .ip4 => |ip4| {
                writeRecordHead(&writer, owner, @backingInt(RecordType.a), answer.ttl_s, 4);
                writer.bytes(&ip4.bytes);
            },
            .ip6 => |ip6| {
                writeRecordHead(&writer, owner, @backingInt(RecordType.aaaa), answer.ttl_s, 16);
                writer.bytes(&ip6.bytes);
            },
        }
    }
    return buffer[0..writer.length];
}

fn addressFits(address: *const IpAddress, record_type: u16) bool {
    return switch (address.*) {
        .ip4 => record_type == @backingInt(RecordType.a),
        .ip6 => record_type == @backingInt(RecordType.aaaa),
    };
}

fn writeRecordHead(writer: *Writer, owner: []const u8, record_type: u16, ttl_s: u32, data_length: u16) void {
    assert(owner.len >= 1);
    assert(data_length >= 1);
    writer.name(owner);
    writer.int(u16, record_type);
    writer.int(u16, class_in);
    writer.int(u32, ttl_s);
    writer.int(u16, data_length);
}

fn testAddress(literal: []const u8) IpAddress {
    return IpAddress.parseLiteral(literal) catch unreachable;
}

/// A query, then the reply a test server writes to it, read back.
fn testExchange(answer: *const Answer, record_type: RecordType, room: []IpAddress) ReadError!Reply {
    var query_buffer: [query_bytes_max]u8 = undefined;
    const query = writeQuery(&query_buffer, 0x1234, "api.internal", record_type);
    const question = readQuery(query).?;
    var reply_buffer: [constants.dns_message_bytes_max]u8 = undefined;
    const reply = writeReply(&reply_buffer, &question, answer);
    return readReply(reply, 0x1234, "api.internal", record_type, 8080, room);
}

test "writeQuery: one question, recursion asked, EDNS0's payload advertised" {
    var buffer: [query_bytes_max]u8 = undefined;
    const query = writeQuery(&buffer, 0xbeef, "api.internal", .aaaa);
    const expected = [_]u8{
        0xbe, 0xef, 0x01, 0x00, 0, 1,   0,   0,   0,   0,    0,    1,
        3,    'a',  'p',  'i',  8, 'i', 'n', 't', 'e', 'r',  'n',  'a',
        'l',  0,    0,    28,   0, 1,
        // OPT: the root, type 41, a 1232-octet payload, no flags, no data.
          0,   0,   41,  0x04, 0xd0, 0,
        0,    0,    0,    0,    0,
    };
    try std.testing.expectEqualSlices(u8, &expected, query);
    const question = readQuery(query).?;
    try std.testing.expectEqual(@as(u16, 0xbeef), question.id);
    try std.testing.expectEqual(@as(u16, 28), question.record_type);
    try std.testing.expectEqualStrings("api.internal", question.host());
}

test "readReply: the addresses the name has, its port, the least TTL" {
    var room: [4]IpAddress = undefined;
    const answer: Answer = .{ .addresses = &.{ testAddress("10.0.0.2:1"), testAddress("10.0.0.1:1"), testAddress("[fd00::1]:1") }, .ttl_s = 45 };
    const reply = try testExchange(&answer, .a, &room);
    try std.testing.expectEqual(Outcome.answered, reply.outcome);
    // AAAA records are not the A query's.
    try std.testing.expectEqual(@as(u16, 2), reply.count);
    try std.testing.expect(room[0].eql(&testAddress("10.0.0.2:8080")));
    try std.testing.expect(room[1].eql(&testAddress("10.0.0.1:8080")));
    try std.testing.expectEqual(@as(u32, 45), reply.ttl_s);
    const six = try testExchange(&answer, .aaaa, &room);
    try std.testing.expectEqual(@as(u16, 1), six.count);
    try std.testing.expect(room[0].eql(&testAddress("[fd00::1]:8080")));
}

test "readReply: a CNAME is followed to the addresses it names" {
    var room: [4]IpAddress = undefined;
    const answer: Answer = .{ .cname = "lb.example.net", .addresses = &.{testAddress("10.0.0.7:1")}, .ttl_s = 9 };
    const reply = try testExchange(&answer, .a, &room);
    try std.testing.expectEqual(@as(u16, 1), reply.count);
    try std.testing.expect(room[0].eql(&testAddress("10.0.0.7:8080")));
}

test "readReply: a CNAME to no record asks the next nameserver, rather than emptying the name" {
    var room: [4]IpAddress = undefined;
    const dangling: Answer = .{ .cname = "lb.example.net" };
    try std.testing.expectEqual(Outcome.failed, (try testExchange(&dangling, .a, &room)).outcome);
}

test "readReply: the RCODEs, the TC bit, and a name with none of the type" {
    var room: [4]IpAddress = undefined;
    try std.testing.expectEqual(Outcome.nxdomain, (try testExchange(&.{ .rcode = 3 }, .a, &room)).outcome);
    try std.testing.expectEqual(Outcome.failed, (try testExchange(&.{ .rcode = 2 }, .a, &room)).outcome);
    try std.testing.expectEqual(Outcome.failed, (try testExchange(&.{ .rcode = 5 }, .a, &room)).outcome);
    const truncated: Answer = .{ .truncated = true, .addresses = &.{testAddress("10.0.0.1:1")} };
    try std.testing.expectEqual(Outcome.truncated, (try testExchange(&truncated, .a, &room)).outcome);
    const nodata = try testExchange(&.{ .addresses = &.{testAddress("[fd00::1]:1")} }, .a, &room);
    try std.testing.expectEqual(Outcome.answered, nodata.outcome);
    try std.testing.expectEqual(@as(u16, 0), nodata.count);
    try std.testing.expectEqual(@as(u32, 0), nodata.ttl_s);
}

test "readReply: past the room, addresses are counted and not written" {
    var room: [2]IpAddress = undefined;
    const answer: Answer = .{ .addresses = &.{ testAddress("10.0.0.1:1"), testAddress("10.0.0.2:1"), testAddress("10.0.0.3:1") } };
    const reply = try testExchange(&answer, .a, &room);
    try std.testing.expectEqual(@as(u16, 2), reply.count);
    try std.testing.expectEqual(@as(u16, 1), reply.dropped);
}

test "readReply: a reply that is not the query's is refused" {
    var room: [2]IpAddress = undefined;
    var query_buffer: [query_bytes_max]u8 = undefined;
    var reply_buffer: [constants.dns_message_bytes_max]u8 = undefined;
    const question = readQuery(writeQuery(&query_buffer, 7, "api.internal", .a)).?;
    const reply = writeReply(&reply_buffer, &question, &.{ .addresses = &.{testAddress("10.0.0.1:1")} });
    // Another ID, another name, another type: none of them answers it.
    try std.testing.expectError(error.Malformed, readReply(reply, 8, "api.internal", .a, 80, &room));
    try std.testing.expectError(error.Malformed, readReply(reply, 7, "api.internals", .a, 80, &room));
    try std.testing.expectError(error.Malformed, readReply(reply, 7, "api.internal", .aaaa, 80, &room));
    // A query is no reply.
    try std.testing.expectError(error.Malformed, readReply(writeQuery(&query_buffer, 7, "api.internal", .a), 7, "api.internal", .a, 80, &room));
    // Cut anywhere, it is refused rather than half read.
    for (0..reply.len) |cut| {
        if (readReply(reply[0..cut], 7, "api.internal", .a, 80, &room)) |read| {
            // A cut past the question may still parse, as fewer records.
            try std.testing.expect(read.count <= 1);
        } else |err| try std.testing.expectEqual(error.Malformed, err);
    }
}

test "readReply: an address owned by another name is not the name's" {
    var room: [2]IpAddress = undefined;
    // The question for `a`, then one A record owned by `b`, which a
    // server cannot hand `a` by placing it in the answer section.
    const reply = [_]u8{
        0, 7,   0x81, 0x80, 0, 1,  0, 1, 0,   0, 0, 0,
        1, 'a', 0,    0,    1, 0,  1, 1, 'b', 0, 0, 1,
        0, 1,   0,    0,    0, 30, 0, 4, 10,  0, 0, 1,
    };
    const read = try readReply(&reply, 7, "a", .a, 80, &room);
    try std.testing.expectEqual(Outcome.answered, read.outcome);
    try std.testing.expectEqual(@as(u16, 0), read.count);
}

test "readReply: compression pointers point back, or the name is refused" {
    var room: [2]IpAddress = undefined;
    // An answer owned by a pointer back to the question's name: read.
    const pointed = [_]u8{
        0, 7,   0x81, 0x80, 0,  1, 0, 1,    0,  0, 0, 0,
        1, 'a', 0,    0,    1,  0, 1, 0xc0, 12, 0, 1, 0,
        1, 0,   0,    0,    30, 0, 4, 10,   0,  0, 1,
    };
    const read = try readReply(&pointed, 7, "a", .a, 80, &room);
    try std.testing.expectEqual(@as(u16, 1), read.count);
    // A pointer to itself, and one forward: refused, never followed.
    var looped = pointed;
    looped[19] = 0xc0;
    looped[20] = 19;
    try std.testing.expectError(error.Malformed, readReply(&looped, 7, "a", .a, 80, &room));
    var forward = pointed;
    forward[20] = 30;
    try std.testing.expectError(error.Malformed, readReply(&forward, 7, "a", .a, 80, &room));
}

test "fuzz: a reply is read or refused, and never past its room" {
    try std.testing.fuzz({}, fuzzReadReply, .{});
}

fn fuzzReadReply(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [constants.dns_message_bytes_max]u8 = undefined;
    const input_len = smith.slice(&input);
    assert(input_len <= input.len);
    const bytes = input[0..input_len];
    var room: [3]IpAddress = undefined;
    const id = replyId(bytes) orelse 0;
    if (readReply(bytes, id, "api.internal", .a, 80, &room)) |reply| {
        assert(reply.count <= room.len);
        if (reply.outcome != .answered) assert(reply.count == 0);
        for (room[0..reply.count]) |*address| {
            assert(address.* == .ip4);
            assert(address.getPort() == 80);
        }
    } else |err| assert(err == error.Malformed);
    // The responder's half reads the same bytes as a query.
    if (readQuery(bytes)) |question| {
        assert(question.host_length <= name_text_bytes_max);
    }
}
