//! A client's reading of the response field sections a server sends
//! (#275), for the scenarios outside `src/http/h2/` — which may not import
//! `h2` (the lint's framing boundary), and so borrow its decoder through
//! this file's plain types. Test support: nothing in the server imports it.

const std = @import("std");
const h2 = @import("h2");

const Session = @import("Session.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

const ResponseReader = @This();

pub const Field = struct { name: []const u8, value: []const u8 };

pub const fields_max: u32 = 64;

table: Session.TableStorage,
decoder: hpack.Decoder,
decoded: [64 * 1024]u8,
fields: [fields_max]Field,

/// In place: the decoder borrows the table's storage.
pub fn init(reader: *ResponseReader) void {
    reader.table = .{};
    reader.decoder = hpack.Decoder.init(reader.table.table(), reader.decoded.len);
}

/// One whole field block, in the order the blocks went out on the
/// connection — the decoder's table carries from each to the next, as a
/// client's does. The fields borrow the reader until the next `decode`.
pub fn decode(reader: *ResponseReader, block: []const u8) ![]const Field {
    var iterator = reader.decoder.iterate(&reader.decoded, block);
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        if (count == fields_max) return error.TooManyFields;
        reader.fields[count] = .{ .name = field.name, .value = field.value };
    }
    assert(count <= fields_max);
    return reader.fields[0..count];
}

/// The first field named `name`, by its exact (lowercase) spelling.
pub fn value(fields: []const Field, name: []const u8) ?[]const u8 {
    assert(name.len >= 1);
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}
