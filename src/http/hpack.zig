//! HPACK header compression (RFC 7541), sans-io and strictly bounded
//! (docs/DESIGN.md §7 Phase 5, slice 2).
//!
//! Decoder: a header block in, headers out. Every decoded name and value is
//! copied into a caller-owned storage buffer, so the output never aliases
//! the mutable dynamic table (a later insert in the same block may evict the
//! entry an earlier field was read from). The dynamic table is a fixed
//! reservation (`constants.h2_header_table_bytes`) — exactly the size we
//! advertise; peer size updates may shrink it, never exceed it.
//!
//! When the decoded list exceeds our bounds (`h2_header_list_bytes_max`,
//! `headers` capacity) decoding *continues* — the dynamic table is shared
//! state that must stay in sync even for a request we will refuse — but
//! nothing more is stored and the bound error is returned at the end.
//! Coding errors (`error.Compression`) abort immediately: they are
//! connection-fatal (COMPRESSION_ERROR), the table state no longer matters.
//!
//! Encoder: stateless minimum — exact static-table match → indexed, static
//! name → indexed name, everything else literal; strings raw, never
//! Huffman-coded, no dynamic-table insertions (peers then hold our table at
//! its zero-cost empty state).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const DecodeError = error{
    /// Malformed HPACK — COMPRESSION_ERROR, connection-fatal (RFC 7541 §2.2).
    Compression,
    /// The decoded header list exceeds our advertised bound, or the storage
    /// buffer — the request is refused (the 431 analogue), the connection
    /// and the dynamic table survive.
    HeaderListTooLarge,
    /// More fields than the caller's headers array — same stream-level class.
    TooManyHeaders,
};

// ---- integer representation (RFC 7541 §5.1) ---------------------------------

/// Decode a prefix-coded integer, advancing `pos`. Values a u32 cannot hold
/// are rejected — every quantity HPACK carries (indices, lengths, sizes) is
/// bounded far below that in this proxy.
fn read_integer(comptime prefix_bits: u4, input: []const u8, pos: *usize) error{Compression}!u32 {
    comptime assert(prefix_bits >= 4 and prefix_bits <= 8);
    if (pos.* >= input.len) return error.Compression;
    const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value: u32 = input[pos.*] & mask;
    pos.* += 1;
    if (value < mask) return value;
    var shift: u6 = 0;
    // Bounded: a u32 spans at most five 7-bit continuation bytes.
    while (shift <= 28) : (shift += 7) {
        if (pos.* >= input.len) return error.Compression;
        const byte = input[pos.*];
        pos.* += 1;
        const sum = @as(u64, value) + (@as(u64, byte & 0x7f) << shift);
        if (sum > std.math.maxInt(u32)) return error.Compression;
        value = @intCast(sum);
        if (byte & 0x80 == 0) return value;
    }
    return error.Compression; // a sixth continuation byte cannot fit a u32
}

/// Encode `value` with the given prefix; `first_byte_bits` carries the
/// pattern above the prefix (e.g. 0x80 for an indexed field).
fn write_integer(
    comptime prefix_bits: u4,
    first_byte_bits: u8,
    value: u32,
    out: []u8,
) error{NoSpace}!usize {
    comptime assert(prefix_bits >= 4 and prefix_bits <= 8);
    const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    assert(first_byte_bits & mask == 0);
    if (out.len < 1) return error.NoSpace;
    if (value < mask) {
        out[0] = first_byte_bits | @as(u8, @intCast(value));
        return 1;
    }
    out[0] = first_byte_bits | mask;
    var remaining: u32 = value - mask;
    var used: usize = 1;
    // Bounded: `remaining` loses 7 bits per iteration (at most 5 for a u32).
    while (remaining >= 0x80) : (remaining >>= 7) {
        if (used == out.len) return error.NoSpace;
        out[used] = @as(u8, @intCast(remaining & 0x7f)) | 0x80;
        used += 1;
    }
    if (used == out.len) return error.NoSpace;
    out[used] = @intCast(remaining);
    return used + 1;
}

// ---- Huffman coding (RFC 7541 §5.2, Appendix B) ------------------------------

const HuffmanCode = struct {
    code: u32,
    bits: u8,
};

/// RFC 7541 Appendix B, symbols 0..255 plus EOS (256), extracted verbatim
/// from the RFC text.
const huffman_codes = [257]HuffmanCode{
    .{ .code = 0x1ff8, .bits = 13 },
    .{ .code = 0x7fffd8, .bits = 23 },
    .{ .code = 0xfffffe2, .bits = 28 },
    .{ .code = 0xfffffe3, .bits = 28 },
    .{ .code = 0xfffffe4, .bits = 28 },
    .{ .code = 0xfffffe5, .bits = 28 },
    .{ .code = 0xfffffe6, .bits = 28 },
    .{ .code = 0xfffffe7, .bits = 28 },
    .{ .code = 0xfffffe8, .bits = 28 },
    .{ .code = 0xffffea, .bits = 24 },
    .{ .code = 0x3ffffffc, .bits = 30 },
    .{ .code = 0xfffffe9, .bits = 28 },
    .{ .code = 0xfffffea, .bits = 28 },
    .{ .code = 0x3ffffffd, .bits = 30 },
    .{ .code = 0xfffffeb, .bits = 28 },
    .{ .code = 0xfffffec, .bits = 28 },
    .{ .code = 0xfffffed, .bits = 28 },
    .{ .code = 0xfffffee, .bits = 28 },
    .{ .code = 0xfffffef, .bits = 28 },
    .{ .code = 0xffffff0, .bits = 28 },
    .{ .code = 0xffffff1, .bits = 28 },
    .{ .code = 0xffffff2, .bits = 28 },
    .{ .code = 0x3ffffffe, .bits = 30 },
    .{ .code = 0xffffff3, .bits = 28 },
    .{ .code = 0xffffff4, .bits = 28 },
    .{ .code = 0xffffff5, .bits = 28 },
    .{ .code = 0xffffff6, .bits = 28 },
    .{ .code = 0xffffff7, .bits = 28 },
    .{ .code = 0xffffff8, .bits = 28 },
    .{ .code = 0xffffff9, .bits = 28 },
    .{ .code = 0xffffffa, .bits = 28 },
    .{ .code = 0xffffffb, .bits = 28 },
    .{ .code = 0x14, .bits = 6 },
    .{ .code = 0x3f8, .bits = 10 },
    .{ .code = 0x3f9, .bits = 10 },
    .{ .code = 0xffa, .bits = 12 },
    .{ .code = 0x1ff9, .bits = 13 },
    .{ .code = 0x15, .bits = 6 },
    .{ .code = 0xf8, .bits = 8 },
    .{ .code = 0x7fa, .bits = 11 },
    .{ .code = 0x3fa, .bits = 10 },
    .{ .code = 0x3fb, .bits = 10 },
    .{ .code = 0xf9, .bits = 8 },
    .{ .code = 0x7fb, .bits = 11 },
    .{ .code = 0xfa, .bits = 8 },
    .{ .code = 0x16, .bits = 6 },
    .{ .code = 0x17, .bits = 6 },
    .{ .code = 0x18, .bits = 6 },
    .{ .code = 0x0, .bits = 5 },
    .{ .code = 0x1, .bits = 5 },
    .{ .code = 0x2, .bits = 5 },
    .{ .code = 0x19, .bits = 6 },
    .{ .code = 0x1a, .bits = 6 },
    .{ .code = 0x1b, .bits = 6 },
    .{ .code = 0x1c, .bits = 6 },
    .{ .code = 0x1d, .bits = 6 },
    .{ .code = 0x1e, .bits = 6 },
    .{ .code = 0x1f, .bits = 6 },
    .{ .code = 0x5c, .bits = 7 },
    .{ .code = 0xfb, .bits = 8 },
    .{ .code = 0x7ffc, .bits = 15 },
    .{ .code = 0x20, .bits = 6 },
    .{ .code = 0xffb, .bits = 12 },
    .{ .code = 0x3fc, .bits = 10 },
    .{ .code = 0x1ffa, .bits = 13 },
    .{ .code = 0x21, .bits = 6 },
    .{ .code = 0x5d, .bits = 7 },
    .{ .code = 0x5e, .bits = 7 },
    .{ .code = 0x5f, .bits = 7 },
    .{ .code = 0x60, .bits = 7 },
    .{ .code = 0x61, .bits = 7 },
    .{ .code = 0x62, .bits = 7 },
    .{ .code = 0x63, .bits = 7 },
    .{ .code = 0x64, .bits = 7 },
    .{ .code = 0x65, .bits = 7 },
    .{ .code = 0x66, .bits = 7 },
    .{ .code = 0x67, .bits = 7 },
    .{ .code = 0x68, .bits = 7 },
    .{ .code = 0x69, .bits = 7 },
    .{ .code = 0x6a, .bits = 7 },
    .{ .code = 0x6b, .bits = 7 },
    .{ .code = 0x6c, .bits = 7 },
    .{ .code = 0x6d, .bits = 7 },
    .{ .code = 0x6e, .bits = 7 },
    .{ .code = 0x6f, .bits = 7 },
    .{ .code = 0x70, .bits = 7 },
    .{ .code = 0x71, .bits = 7 },
    .{ .code = 0x72, .bits = 7 },
    .{ .code = 0xfc, .bits = 8 },
    .{ .code = 0x73, .bits = 7 },
    .{ .code = 0xfd, .bits = 8 },
    .{ .code = 0x1ffb, .bits = 13 },
    .{ .code = 0x7fff0, .bits = 19 },
    .{ .code = 0x1ffc, .bits = 13 },
    .{ .code = 0x3ffc, .bits = 14 },
    .{ .code = 0x22, .bits = 6 },
    .{ .code = 0x7ffd, .bits = 15 },
    .{ .code = 0x3, .bits = 5 },
    .{ .code = 0x23, .bits = 6 },
    .{ .code = 0x4, .bits = 5 },
    .{ .code = 0x24, .bits = 6 },
    .{ .code = 0x5, .bits = 5 },
    .{ .code = 0x25, .bits = 6 },
    .{ .code = 0x26, .bits = 6 },
    .{ .code = 0x27, .bits = 6 },
    .{ .code = 0x6, .bits = 5 },
    .{ .code = 0x74, .bits = 7 },
    .{ .code = 0x75, .bits = 7 },
    .{ .code = 0x28, .bits = 6 },
    .{ .code = 0x29, .bits = 6 },
    .{ .code = 0x2a, .bits = 6 },
    .{ .code = 0x7, .bits = 5 },
    .{ .code = 0x2b, .bits = 6 },
    .{ .code = 0x76, .bits = 7 },
    .{ .code = 0x2c, .bits = 6 },
    .{ .code = 0x8, .bits = 5 },
    .{ .code = 0x9, .bits = 5 },
    .{ .code = 0x2d, .bits = 6 },
    .{ .code = 0x77, .bits = 7 },
    .{ .code = 0x78, .bits = 7 },
    .{ .code = 0x79, .bits = 7 },
    .{ .code = 0x7a, .bits = 7 },
    .{ .code = 0x7b, .bits = 7 },
    .{ .code = 0x7ffe, .bits = 15 },
    .{ .code = 0x7fc, .bits = 11 },
    .{ .code = 0x3ffd, .bits = 14 },
    .{ .code = 0x1ffd, .bits = 13 },
    .{ .code = 0xffffffc, .bits = 28 },
    .{ .code = 0xfffe6, .bits = 20 },
    .{ .code = 0x3fffd2, .bits = 22 },
    .{ .code = 0xfffe7, .bits = 20 },
    .{ .code = 0xfffe8, .bits = 20 },
    .{ .code = 0x3fffd3, .bits = 22 },
    .{ .code = 0x3fffd4, .bits = 22 },
    .{ .code = 0x3fffd5, .bits = 22 },
    .{ .code = 0x7fffd9, .bits = 23 },
    .{ .code = 0x3fffd6, .bits = 22 },
    .{ .code = 0x7fffda, .bits = 23 },
    .{ .code = 0x7fffdb, .bits = 23 },
    .{ .code = 0x7fffdc, .bits = 23 },
    .{ .code = 0x7fffdd, .bits = 23 },
    .{ .code = 0x7fffde, .bits = 23 },
    .{ .code = 0xffffeb, .bits = 24 },
    .{ .code = 0x7fffdf, .bits = 23 },
    .{ .code = 0xffffec, .bits = 24 },
    .{ .code = 0xffffed, .bits = 24 },
    .{ .code = 0x3fffd7, .bits = 22 },
    .{ .code = 0x7fffe0, .bits = 23 },
    .{ .code = 0xffffee, .bits = 24 },
    .{ .code = 0x7fffe1, .bits = 23 },
    .{ .code = 0x7fffe2, .bits = 23 },
    .{ .code = 0x7fffe3, .bits = 23 },
    .{ .code = 0x7fffe4, .bits = 23 },
    .{ .code = 0x1fffdc, .bits = 21 },
    .{ .code = 0x3fffd8, .bits = 22 },
    .{ .code = 0x7fffe5, .bits = 23 },
    .{ .code = 0x3fffd9, .bits = 22 },
    .{ .code = 0x7fffe6, .bits = 23 },
    .{ .code = 0x7fffe7, .bits = 23 },
    .{ .code = 0xffffef, .bits = 24 },
    .{ .code = 0x3fffda, .bits = 22 },
    .{ .code = 0x1fffdd, .bits = 21 },
    .{ .code = 0xfffe9, .bits = 20 },
    .{ .code = 0x3fffdb, .bits = 22 },
    .{ .code = 0x3fffdc, .bits = 22 },
    .{ .code = 0x7fffe8, .bits = 23 },
    .{ .code = 0x7fffe9, .bits = 23 },
    .{ .code = 0x1fffde, .bits = 21 },
    .{ .code = 0x7fffea, .bits = 23 },
    .{ .code = 0x3fffdd, .bits = 22 },
    .{ .code = 0x3fffde, .bits = 22 },
    .{ .code = 0xfffff0, .bits = 24 },
    .{ .code = 0x1fffdf, .bits = 21 },
    .{ .code = 0x3fffdf, .bits = 22 },
    .{ .code = 0x7fffeb, .bits = 23 },
    .{ .code = 0x7fffec, .bits = 23 },
    .{ .code = 0x1fffe0, .bits = 21 },
    .{ .code = 0x1fffe1, .bits = 21 },
    .{ .code = 0x3fffe0, .bits = 22 },
    .{ .code = 0x1fffe2, .bits = 21 },
    .{ .code = 0x7fffed, .bits = 23 },
    .{ .code = 0x3fffe1, .bits = 22 },
    .{ .code = 0x7fffee, .bits = 23 },
    .{ .code = 0x7fffef, .bits = 23 },
    .{ .code = 0xfffea, .bits = 20 },
    .{ .code = 0x3fffe2, .bits = 22 },
    .{ .code = 0x3fffe3, .bits = 22 },
    .{ .code = 0x3fffe4, .bits = 22 },
    .{ .code = 0x7ffff0, .bits = 23 },
    .{ .code = 0x3fffe5, .bits = 22 },
    .{ .code = 0x3fffe6, .bits = 22 },
    .{ .code = 0x7ffff1, .bits = 23 },
    .{ .code = 0x3ffffe0, .bits = 26 },
    .{ .code = 0x3ffffe1, .bits = 26 },
    .{ .code = 0xfffeb, .bits = 20 },
    .{ .code = 0x7fff1, .bits = 19 },
    .{ .code = 0x3fffe7, .bits = 22 },
    .{ .code = 0x7ffff2, .bits = 23 },
    .{ .code = 0x3fffe8, .bits = 22 },
    .{ .code = 0x1ffffec, .bits = 25 },
    .{ .code = 0x3ffffe2, .bits = 26 },
    .{ .code = 0x3ffffe3, .bits = 26 },
    .{ .code = 0x3ffffe4, .bits = 26 },
    .{ .code = 0x7ffffde, .bits = 27 },
    .{ .code = 0x7ffffdf, .bits = 27 },
    .{ .code = 0x3ffffe5, .bits = 26 },
    .{ .code = 0xfffff1, .bits = 24 },
    .{ .code = 0x1ffffed, .bits = 25 },
    .{ .code = 0x7fff2, .bits = 19 },
    .{ .code = 0x1fffe3, .bits = 21 },
    .{ .code = 0x3ffffe6, .bits = 26 },
    .{ .code = 0x7ffffe0, .bits = 27 },
    .{ .code = 0x7ffffe1, .bits = 27 },
    .{ .code = 0x3ffffe7, .bits = 26 },
    .{ .code = 0x7ffffe2, .bits = 27 },
    .{ .code = 0xfffff2, .bits = 24 },
    .{ .code = 0x1fffe4, .bits = 21 },
    .{ .code = 0x1fffe5, .bits = 21 },
    .{ .code = 0x3ffffe8, .bits = 26 },
    .{ .code = 0x3ffffe9, .bits = 26 },
    .{ .code = 0xffffffd, .bits = 28 },
    .{ .code = 0x7ffffe3, .bits = 27 },
    .{ .code = 0x7ffffe4, .bits = 27 },
    .{ .code = 0x7ffffe5, .bits = 27 },
    .{ .code = 0xfffec, .bits = 20 },
    .{ .code = 0xfffff3, .bits = 24 },
    .{ .code = 0xfffed, .bits = 20 },
    .{ .code = 0x1fffe6, .bits = 21 },
    .{ .code = 0x3fffe9, .bits = 22 },
    .{ .code = 0x1fffe7, .bits = 21 },
    .{ .code = 0x1fffe8, .bits = 21 },
    .{ .code = 0x7ffff3, .bits = 23 },
    .{ .code = 0x3fffea, .bits = 22 },
    .{ .code = 0x3fffeb, .bits = 22 },
    .{ .code = 0x1ffffee, .bits = 25 },
    .{ .code = 0x1ffffef, .bits = 25 },
    .{ .code = 0xfffff4, .bits = 24 },
    .{ .code = 0xfffff5, .bits = 24 },
    .{ .code = 0x3ffffea, .bits = 26 },
    .{ .code = 0x7ffff4, .bits = 23 },
    .{ .code = 0x3ffffeb, .bits = 26 },
    .{ .code = 0x7ffffe6, .bits = 27 },
    .{ .code = 0x3ffffec, .bits = 26 },
    .{ .code = 0x3ffffed, .bits = 26 },
    .{ .code = 0x7ffffe7, .bits = 27 },
    .{ .code = 0x7ffffe8, .bits = 27 },
    .{ .code = 0x7ffffe9, .bits = 27 },
    .{ .code = 0x7ffffea, .bits = 27 },
    .{ .code = 0x7ffffeb, .bits = 27 },
    .{ .code = 0xffffffe, .bits = 28 },
    .{ .code = 0x7ffffec, .bits = 27 },
    .{ .code = 0x7ffffed, .bits = 27 },
    .{ .code = 0x7ffffee, .bits = 27 },
    .{ .code = 0x7ffffef, .bits = 27 },
    .{ .code = 0x7fffff0, .bits = 27 },
    .{ .code = 0x3ffffee, .bits = 26 },
    .{ .code = 0x3fffffff, .bits = 30 },
};

const huffman_leaf_flag: u16 = 0x8000;
const huffman_symbol_mask: u16 = 0x1ff;

/// Binary decode tree, built at comptime from the code table. 257 leaves
/// need exactly 256 internal nodes; a child value with the leaf flag set
/// carries the symbol, otherwise it indexes the next node.
const huffman_nodes = build: {
    @setEvalBranchQuota(200_000);
    var nodes = [_][2]u16{.{ 0, 0 }} ** 256;
    var node_count: u16 = 1; // node 0 is the root
    for (huffman_codes, 0..) |entry, symbol| {
        var node: u16 = 0;
        var remaining: u8 = entry.bits;
        while (remaining > 0) {
            remaining -= 1;
            const bit = (entry.code >> @intCast(remaining)) & 1;
            if (remaining == 0) {
                nodes[node][bit] = huffman_leaf_flag | @as(u16, symbol);
            } else {
                if (nodes[node][bit] == 0) {
                    nodes[node][bit] = node_count;
                    node_count += 1;
                }
                node = nodes[node][bit];
            }
        }
    }
    if (node_count != 256) @compileError("Huffman code table is not canonical");
    // A canonical Huffman code is complete: every internal node has two
    // children, so the decoder can never step into a hole.
    for (nodes) |children| {
        if (children[0] == 0 or children[1] == 0) @compileError("Huffman tree is incomplete");
    }
    break :build nodes;
};

/// Walk a Huffman-coded string, returning the decoded length; when `out` is
/// provided (sized by a prior counting call), also write the bytes. Errors:
/// the EOS symbol inside the data, or final padding that is not a proper
/// EOS prefix — fewer than 8 bits, all ones (RFC 7541 §5.2).
fn huffman_decode(encoded: []const u8, out: ?[]u8) error{Compression}!usize {
    var node: u16 = 0;
    var length: usize = 0;
    var padding_bits: u8 = 0;
    var padding_ones = true;
    for (encoded) |byte| {
        var bit_index: u8 = 8;
        while (bit_index > 0) {
            bit_index -= 1;
            const bit: u1 = @intCast((byte >> @as(u3, @intCast(bit_index))) & 1);
            padding_bits += 1;
            padding_ones = padding_ones and bit == 1;
            const next = huffman_nodes[node][bit];
            assert(next != 0); // the tree is complete (checked at comptime)
            if (next & huffman_leaf_flag == 0) {
                node = next;
                continue;
            }
            const symbol = next & huffman_symbol_mask;
            if (symbol == 256) return error.Compression; // EOS inside the data
            if (out) |bytes| {
                assert(length < bytes.len); // sized by the counting pass
                bytes[length] = @intCast(symbol);
            }
            length += 1;
            node = 0;
            padding_bits = 0;
            padding_ones = true;
        }
    }
    assert(padding_bits <= 30); // the longest code path resets or errors
    if (padding_bits > 7 or !padding_ones) return error.Compression;
    return length;
}

// ---- string literals (RFC 7541 §5.2) ----------------------------------------

/// A string literal, located and fully validated but not yet decoded — the
/// decoded length is known, so the caller can bounds-check before writing.
const StringRef = struct {
    encoded: []const u8,
    decoded_len: u32,
    huffman: bool,

    fn decode_into(string: StringRef, out: []u8) void {
        assert(out.len == string.decoded_len);
        if (string.huffman) {
            // Validated by read_string's counting pass — cannot fail here.
            const length = huffman_decode(string.encoded, out) catch unreachable;
            assert(length == string.decoded_len);
        } else {
            @memcpy(out, string.encoded);
        }
    }
};

/// Read a string literal at `pos`, validating Huffman coding via a counting
/// pass, and advance past it.
fn read_string(input: []const u8, pos: *usize) error{Compression}!StringRef {
    if (pos.* >= input.len) return error.Compression;
    const huffman = input[pos.*] & 0x80 != 0;
    const length = try read_integer(7, input, pos);
    if (length > input.len - pos.*) return error.Compression;
    const encoded = input[pos.*..][0..length];
    pos.* += length;
    const decoded_len = if (huffman) try huffman_decode(encoded, null) else length;
    assert(decoded_len <= 2 * @as(usize, length) or length < 2); // shortest code is 5 bits
    return .{ .encoded = encoded, .decoded_len = @intCast(decoded_len), .huffman = huffman };
}

// ---- tables (RFC 7541 §2.3, Appendix A) --------------------------------------

/// The static table, indices 1..61, extracted verbatim from the RFC text.
pub const static_table = [61]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// The dynamic table: a fixed byte reservation holding entry name/value
/// bytes oldest-first, plus fixed entry metadata. FIFO eviction compacts
/// the byte storage forward — at most `h2_header_table_bytes` moved per
/// insert, off the per-byte relay path.
pub const DynamicTable = struct {
    storage: [constants.h2_header_table_bytes]u8 = undefined,
    entries: [entries_max]Entry = undefined,
    count: u32 = 0,
    /// Bytes of `storage` in use.
    used: u32 = 0,
    /// Current size per RFC 7541 §4.1: stored bytes + 32 per entry.
    size: u32 = 0,
    /// Current maximum, moved by encoder size updates (§6.3).
    size_max: u32 = constants.h2_header_table_bytes,
    /// What we advertised (SETTINGS_HEADER_TABLE_SIZE) — the bound size
    /// updates may not exceed. Tests shrink it to replay the RFC examples.
    size_limit: u32 = constants.h2_header_table_bytes,

    /// The smallest possible entry is the empty header: `entry_overhead`
    /// bytes of accounting, so the entry count is bounded by capacity / 32.
    pub const entry_overhead = 32;
    pub const entries_max = constants.h2_header_table_bytes / entry_overhead;

    const Entry = struct {
        offset: u16,
        name_len: u16,
        value_len: u16,
    };

    comptime {
        assert(constants.h2_header_table_bytes <= std.math.maxInt(u16) + 1);
        assert(entries_max >= 1);
    }

    /// Look up by dynamic index (1 = newest, per §2.3.3 after subtracting
    /// the static table). The returned slices alias the table storage:
    /// valid only until the next insert or resize.
    pub fn get(table: *const DynamicTable, index: u32) ?Header {
        if (index == 0 or index > table.count) return null;
        const entry = table.entries[table.count - index];
        assert(@as(u32, entry.offset) + entry.name_len + entry.value_len <= table.used);
        return .{
            .name = table.storage[entry.offset..][0..entry.name_len],
            .value = table.storage[entry.offset + entry.name_len ..][0..entry.value_len],
        };
    }

    /// Insert an entry, evicting oldest-first to make room. An entry larger
    /// than the current maximum clears the table — not an error (§4.4).
    /// The sources must not alias the table's own storage.
    pub fn insert(table: *DynamicTable, name: []const u8, value: []const u8) void {
        assert(table.alias_free(name));
        assert(table.alias_free(value));
        const entry_size = name.len + value.len + entry_overhead;
        if (entry_size > table.size_max) {
            table.clear();
            return;
        }
        table.evict_to(table.size_max - @as(u32, @intCast(entry_size)));
        assert(table.count < entries_max);
        const offset = table.used;
        @memcpy(table.storage[offset..][0..name.len], name);
        @memcpy(table.storage[offset + name.len ..][0..value.len], value);
        table.entries[table.count] = .{
            .offset = @intCast(offset),
            .name_len = @intCast(name.len),
            .value_len = @intCast(value.len),
        };
        table.count += 1;
        table.used += @intCast(name.len + value.len);
        table.size += @intCast(entry_size);
        assert(table.size == table.used + entry_overhead * table.count);
    }

    /// An encoder-driven size update (§6.3); above the advertised limit is
    /// a coding error.
    pub fn resize(table: *DynamicTable, size_new: u32) error{Compression}!void {
        if (size_new > table.size_limit) return error.Compression;
        table.size_max = size_new;
        table.evict_to(size_new);
    }

    pub fn clear(table: *DynamicTable) void {
        table.count = 0;
        table.used = 0;
        table.size = 0;
    }

    /// Evict oldest entries until `size <= target`, compacting storage.
    fn evict_to(table: *DynamicTable, target: u32) void {
        var drop_count: u32 = 0;
        var drop_bytes: u32 = 0;
        var kept_size = table.size;
        // Bounded by the entry count; an eviction always makes progress.
        while (kept_size > target) {
            assert(drop_count < table.count);
            const entry = table.entries[drop_count];
            kept_size -= @as(u32, entry.name_len) + entry.value_len + entry_overhead;
            drop_bytes += @as(u32, entry.name_len) + entry.value_len;
            drop_count += 1;
        }
        if (drop_count == 0) return;
        std.mem.copyForwards(
            u8,
            table.storage[0 .. table.used - drop_bytes],
            table.storage[drop_bytes..table.used],
        );
        for (drop_count..table.count) |index| {
            var entry = table.entries[index];
            entry.offset -= @intCast(drop_bytes);
            table.entries[index - drop_count] = entry;
        }
        table.count -= drop_count;
        table.used -= drop_bytes;
        table.size = kept_size;
        assert(table.size == table.used + entry_overhead * table.count);
    }

    /// True when `bytes` does not point into the table's own storage —
    /// inserting from the table would read from memory eviction just moved.
    fn alias_free(table: *const DynamicTable, bytes: []const u8) bool {
        if (bytes.len == 0) return true;
        const storage_start = @intFromPtr(&table.storage);
        const storage_end = storage_start + table.storage.len;
        const bytes_start = @intFromPtr(bytes.ptr);
        return bytes_start + bytes.len <= storage_start or bytes_start >= storage_end;
    }
};

// ---- decoder -----------------------------------------------------------------

/// Accumulates decoded fields into the caller's arrays. When a bound trips,
/// the error is held (`bound_error`) and later fields are discarded — but
/// the caller keeps decoding so the dynamic table stays in sync.
const Output = struct {
    headers: []Header,
    storage: []u8,
    count: u32 = 0,
    used: u32 = 0,
    list_size: u64 = 0,
    bound_error: ?DecodeError = null,

    /// Account for a field and say whether it should be stored.
    fn admit(output: *Output, name_len: u32, value_len: u32) bool {
        if (output.bound_error != null) return false;
        const field_size = @as(u64, name_len) + value_len + DynamicTable.entry_overhead;
        if (output.list_size + field_size > constants.h2_header_list_bytes_max) {
            output.bound_error = error.HeaderListTooLarge;
            return false;
        }
        if (output.count == output.headers.len) {
            output.bound_error = error.TooManyHeaders;
            return false;
        }
        if (@as(u64, output.used) + name_len + value_len > output.storage.len) {
            output.bound_error = error.HeaderListTooLarge;
            return false;
        }
        output.list_size += field_size;
        return true;
    }

    fn copy(output: *Output, bytes: []const u8) []const u8 {
        assert(output.used + bytes.len <= output.storage.len); // admit() checked
        const target = output.storage[output.used..][0..bytes.len];
        @memcpy(target, bytes);
        output.used += @intCast(bytes.len);
        return target;
    }

    fn place(output: *Output, string: StringRef) []const u8 {
        assert(output.used + string.decoded_len <= output.storage.len); // admit() checked
        const target = output.storage[output.used..][0..string.decoded_len];
        string.decode_into(target);
        output.used += string.decoded_len;
        return target;
    }

    fn push(output: *Output, name: []const u8, value: []const u8) void {
        assert(output.count < output.headers.len);
        output.headers[output.count] = .{ .name = name, .value = value };
        output.count += 1;
    }
};

pub const Decoder = struct {
    table: DynamicTable = .{},

    /// Decode one complete header block. Every returned name and value is a
    /// slice of `storage` — stable, never aliasing the dynamic table. Size
    /// `storage` at `h2_header_list_bytes_max` so the list bound, not the
    /// buffer, is what limits a request.
    pub fn decode(
        decoder: *Decoder,
        input: []const u8,
        headers: []Header,
        storage: []u8,
    ) DecodeError![]const Header {
        assert(headers.len > 0);
        var pos: usize = 0;
        var output = Output{ .headers = headers, .storage = storage };
        var fields: u32 = 0;
        var size_updates: u32 = 0;
        // Bounded: every iteration consumes at least one input byte.
        while (pos < input.len) {
            const first = input[pos];
            if (first & 0x80 != 0) {
                // Indexed field (§6.1). Copied out even from the static
                // table — uniform lifetime for every output slice.
                const index = try read_integer(7, input, &pos);
                const field = decoder.lookup(index) orelse return error.Compression;
                if (output.admit(@intCast(field.name.len), @intCast(field.value.len))) {
                    const name = output.copy(field.name);
                    const value = output.copy(field.value);
                    output.push(name, value);
                }
                fields += 1;
            } else if (first & 0x40 != 0) {
                // Literal with incremental indexing (§6.2.1).
                try decoder.decode_literal(6, true, input, &pos, &output);
                fields += 1;
            } else if (first & 0x20 != 0) {
                // Dynamic table size update (§6.3): only before the first
                // field of a block, and at most two (shrink then grow).
                if (fields != 0 or size_updates == 2) return error.Compression;
                size_updates += 1;
                try decoder.table.resize(try read_integer(5, input, &pos));
            } else {
                // Literal without indexing (§6.2.2, 0x00) or never indexed
                // (§6.2.3, 0x10): we forward and never re-index, so both
                // decode identically.
                try decoder.decode_literal(4, false, input, &pos, &output);
                fields += 1;
            }
        }
        assert(pos == input.len);
        if (output.bound_error) |bound_error| return bound_error;
        return output.headers[0..output.count];
    }

    /// Index across both tables: 1..61 static, above that dynamic (§2.3.3).
    fn lookup(decoder: *const Decoder, index: u32) ?Header {
        if (index == 0) return null;
        if (index <= static_table.len) return static_table[index - 1];
        return decoder.table.get(@intCast(index - static_table.len));
    }

    fn decode_literal(
        decoder: *Decoder,
        comptime prefix_bits: u4,
        insert: bool,
        input: []const u8,
        pos: *usize,
        output: *Output,
    ) DecodeError!void {
        const name_index = try read_integer(prefix_bits, input, pos);
        const name_string: ?StringRef = if (name_index == 0) try read_string(input, pos) else null;
        const name_len: u32 = if (name_string) |string|
            string.decoded_len
        else if (decoder.lookup(name_index)) |field|
            @intCast(field.name.len)
        else
            return error.Compression;
        const value_string = try read_string(input, pos);

        var name: []const u8 = undefined;
        var value: []const u8 = undefined;
        const stored = output.admit(name_len, value_string.decoded_len);
        if (stored) {
            // The name is copied out of the tables *before* the insert
            // below may evict its source entry.
            name = if (name_string) |string|
                output.place(string)
            else
                output.copy(decoder.lookup(name_index).?.name);
            value = output.place(value_string);
            output.push(name, value);
        }
        if (!insert) return;

        const entry_size = @as(u64, name_len) + value_string.decoded_len +
            DynamicTable.entry_overhead;
        if (entry_size > decoder.table.size_max) {
            // Too large to ever reside in the table: everything is evicted
            // instead (§4.4). The field itself was still emitted above.
            decoder.table.clear();
            return;
        }
        var scratch: [constants.h2_header_table_bytes]u8 = undefined;
        if (!stored) {
            // Discarded field, but the peer's encoder indexed it — decode
            // into scratch so the shared table state stays in sync.
            assert(name_len + value_string.decoded_len <= scratch.len); // entry fits size_max
            if (name_string) |string| {
                string.decode_into(scratch[0..name_len]);
            } else {
                @memcpy(scratch[0..name_len], decoder.lookup(name_index).?.name);
            }
            value_string.decode_into(scratch[name_len..][0..value_string.decoded_len]);
            name = scratch[0..name_len];
            value = scratch[name_len..][0..value_string.decoded_len];
        }
        decoder.table.insert(name, value);
    }
};

// ---- encoder -----------------------------------------------------------------

/// Encode one field: an exact static-table match becomes an indexed field, a
/// static name match indexes just the name, anything else is fully literal
/// (§6.2.2, "without indexing"). Strings are raw, never Huffman-coded, and
/// the dynamic table is never used — the encoder is stateless.
pub fn encode_header(name: []const u8, value: []const u8, out: []u8) error{NoSpace}!usize {
    assert(name.len > 0);
    var name_index: u32 = 0;
    for (static_table, 1..) |entry, index| { // bounded: 61 static entries
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (name_index == 0) name_index = @intCast(index);
        if (std.mem.eql(u8, entry.value, value)) {
            return write_integer(7, 0x80, @intCast(index), out);
        }
    }
    var used: usize = try write_integer(4, 0x00, name_index, out);
    if (name_index == 0) used += try write_string(name, out[used..]);
    used += try write_string(value, out[used..]);
    assert(used <= out.len);
    return used;
}

fn write_string(bytes: []const u8, out: []u8) error{NoSpace}!usize {
    const used = try write_integer(7, 0x00, @intCast(bytes.len), out);
    if (out.len - used < bytes.len) return error.NoSpace;
    @memcpy(out[used..][0..bytes.len], bytes);
    return used + bytes.len;
}

// ---- tests -------------------------------------------------------------------

const testing = std.testing;

/// Decode hex (whitespace-free) into a test buffer.
fn hex_bytes(hex: []const u8, out: []u8) []const u8 {
    assert(hex.len % 2 == 0);
    assert(out.len >= hex.len / 2);
    for (0..hex.len / 2) |index| {
        out[index] = std.fmt.parseInt(u8, hex[index * 2 ..][0..2], 16) catch unreachable;
    }
    return out[0 .. hex.len / 2];
}

fn expect_header(header: Header, name: []const u8, value: []const u8) !void {
    try testing.expectEqualStrings(name, header.name);
    try testing.expectEqualStrings(value, header.value);
}

test "hpack: integer representation (RFC 7541 C.1)" {
    var out: [8]u8 = undefined;
    // C.1.1: 10, 5-bit prefix -> 0x0a.
    try testing.expectEqual(@as(usize, 1), try write_integer(5, 0, 10, &out));
    try testing.expectEqual(@as(u8, 0x0a), out[0]);
    var pos: usize = 0;
    try testing.expectEqual(@as(u32, 10), try read_integer(5, out[0..1], &pos));
    // C.1.2: 1337, 5-bit prefix -> 1f 9a 0a.
    try testing.expectEqual(@as(usize, 3), try write_integer(5, 0, 1337, &out));
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, out[0..3]);
    pos = 0;
    try testing.expectEqual(@as(u32, 1337), try read_integer(5, out[0..3], &pos));
    // C.1.3: 42, 8-bit prefix -> 2a.
    try testing.expectEqual(@as(usize, 1), try write_integer(8, 0, 42, &out));
    try testing.expectEqual(@as(u8, 0x2a), out[0]);
}

test "hpack: integer decoding rejects overflow and truncation" {
    var pos: usize = 0;
    // Six continuation bytes cannot fit a u32.
    const wide = [_]u8{ 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
    try testing.expectError(error.Compression, read_integer(5, &wide, &pos));
    // A sum past maxInt(u32).
    pos = 0;
    const overflow = [_]u8{ 0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f };
    try testing.expectError(error.Compression, read_integer(5, &overflow, &pos));
    // Continuation promised but absent.
    pos = 0;
    const truncated = [_]u8{ 0x1f, 0x80 };
    try testing.expectError(error.Compression, read_integer(5, &truncated, &pos));
}

test "hpack: literal header fields (RFC 7541 C.2)" {
    var buffer: [64]u8 = undefined;
    var headers: [8]Header = undefined;
    var storage: [256]u8 = undefined;

    // C.2.1: literal with incremental indexing.
    var decoder = Decoder{};
    const with_indexing =
        hex_bytes("400a637573746f6d2d6b65790d637573746f6d2d686561646572", &buffer);
    const one = try decoder.decode(with_indexing, &headers, &storage);
    try testing.expectEqual(@as(usize, 1), one.len);
    try expect_header(one[0], "custom-key", "custom-header");
    try testing.expectEqual(@as(u32, 55), decoder.table.size);
    try expect_header(decoder.table.get(1).?, "custom-key", "custom-header");

    // C.2.2: literal without indexing (indexed name :path).
    decoder = Decoder{};
    const without = hex_bytes("040c2f73616d706c652f70617468", &buffer);
    const two = try decoder.decode(without, &headers, &storage);
    try expect_header(two[0], ":path", "/sample/path");
    try testing.expectEqual(@as(u32, 0), decoder.table.size);

    // C.2.3: literal never indexed.
    decoder = Decoder{};
    const never = hex_bytes("100870617373776f726406736563726574", &buffer);
    const three = try decoder.decode(never, &headers, &storage);
    try expect_header(three[0], "password", "secret");
    try testing.expectEqual(@as(u32, 0), decoder.table.size);

    // C.2.4: indexed field.
    decoder = Decoder{};
    const indexed = hex_bytes("82", &buffer);
    const four = try decoder.decode(indexed, &headers, &storage);
    try expect_header(four[0], ":method", "GET");
}

test "hpack: request examples without Huffman coding (RFC 7541 C.3)" {
    var buffer: [64]u8 = undefined;
    var headers: [8]Header = undefined;
    var storage: [512]u8 = undefined;
    var decoder = Decoder{};

    const first = try decoder.decode(
        hex_bytes("828684410f7777772e6578616d706c652e636f6d", &buffer),
        &headers,
        &storage,
    );
    try testing.expectEqual(@as(usize, 4), first.len);
    try expect_header(first[0], ":method", "GET");
    try expect_header(first[1], ":scheme", "http");
    try expect_header(first[2], ":path", "/");
    try expect_header(first[3], ":authority", "www.example.com");
    try testing.expectEqual(@as(u32, 57), decoder.table.size);

    const second = try decoder.decode(
        hex_bytes("828684be58086e6f2d6361636865", &buffer),
        &headers,
        &storage,
    );
    try testing.expectEqual(@as(usize, 5), second.len);
    try expect_header(second[3], ":authority", "www.example.com"); // via dynamic index 62
    try expect_header(second[4], "cache-control", "no-cache");
    try testing.expectEqual(@as(u32, 110), decoder.table.size);

    const third = try decoder.decode(
        hex_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", &buffer),
        &headers,
        &storage,
    );
    try testing.expectEqual(@as(usize, 5), third.len);
    try expect_header(third[1], ":scheme", "https");
    try expect_header(third[2], ":path", "/index.html");
    try expect_header(third[4], "custom-key", "custom-value");
    try testing.expectEqual(@as(u32, 164), decoder.table.size);
    try testing.expectEqual(@as(u32, 3), decoder.table.count);
    try expect_header(decoder.table.get(1).?, "custom-key", "custom-value");
    try expect_header(decoder.table.get(3).?, ":authority", "www.example.com");
}

test "hpack: request examples with Huffman coding (RFC 7541 C.4)" {
    var buffer: [64]u8 = undefined;
    var headers: [8]Header = undefined;
    var storage: [512]u8 = undefined;
    var decoder = Decoder{};

    const first = try decoder.decode(
        hex_bytes("828684418cf1e3c2e5f23a6ba0ab90f4ff", &buffer),
        &headers,
        &storage,
    );
    try expect_header(first[3], ":authority", "www.example.com");
    try testing.expectEqual(@as(u32, 57), decoder.table.size);

    const second = try decoder.decode(
        hex_bytes("828684be5886a8eb10649cbf", &buffer),
        &headers,
        &storage,
    );
    try expect_header(second[4], "cache-control", "no-cache");
    try testing.expectEqual(@as(u32, 110), decoder.table.size);

    const third = try decoder.decode(
        hex_bytes("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", &buffer),
        &headers,
        &storage,
    );
    try expect_header(third[4], "custom-key", "custom-value");
    try testing.expectEqual(@as(u32, 164), decoder.table.size);
}

test "hpack: response examples with eviction (RFC 7541 C.5)" {
    var buffer: [128]u8 = undefined;
    var headers: [8]Header = undefined;
    var storage: [512]u8 = undefined;
    var decoder = Decoder{};
    // The examples run with SETTINGS_HEADER_TABLE_SIZE = 256.
    decoder.table.size_limit = 256;
    decoder.table.size_max = 256;

    const first = try decoder.decode(hex_bytes(
        "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a" ++
            "323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        &buffer,
    ), &headers, &storage);
    try testing.expectEqual(@as(usize, 4), first.len);
    try expect_header(first[0], ":status", "302");
    try expect_header(first[1], "cache-control", "private");
    try expect_header(first[2], "date", "Mon, 21 Oct 2013 20:13:21 GMT");
    try expect_header(first[3], "location", "https://www.example.com");
    try testing.expectEqual(@as(u32, 222), decoder.table.size);
    try testing.expectEqual(@as(u32, 4), decoder.table.count);

    // The second response evicts ":status 302" to admit ":status 307".
    const second = try decoder.decode(hex_bytes("4803333037c1c0bf", &buffer), &headers, &storage);
    try testing.expectEqual(@as(usize, 4), second.len);
    try expect_header(second[0], ":status", "307");
    try expect_header(second[3], "location", "https://www.example.com");
    try testing.expectEqual(@as(u32, 222), decoder.table.size);
    try expect_header(decoder.table.get(1).?, ":status", "307");

    const third = try decoder.decode(hex_bytes(
        "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69" ++
            "707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d6178" ++
            "2d6167653d333630303b2076657273696f6e3d31",
        &buffer,
    ), &headers, &storage);
    try testing.expectEqual(@as(usize, 6), third.len);
    try expect_header(third[0], ":status", "200");
    try expect_header(third[2], "date", "Mon, 21 Oct 2013 20:13:22 GMT");
    try expect_header(third[4], "content-encoding", "gzip");
    try expect_header(
        third[5],
        "set-cookie",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    );
    try testing.expectEqual(@as(u32, 215), decoder.table.size);
    try testing.expectEqual(@as(u32, 3), decoder.table.count);
}

test "hpack: response examples with Huffman coding (RFC 7541 C.6)" {
    var buffer: [128]u8 = undefined;
    var headers: [8]Header = undefined;
    var storage: [512]u8 = undefined;
    var decoder = Decoder{};
    decoder.table.size_limit = 256;
    decoder.table.size_max = 256;

    const first = try decoder.decode(hex_bytes(
        "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29" ++
            "ad171863c78f0b97c8e9ae82ae43d3",
        &buffer,
    ), &headers, &storage);
    try expect_header(first[0], ":status", "302");
    try expect_header(first[2], "date", "Mon, 21 Oct 2013 20:13:21 GMT");
    try expect_header(first[3], "location", "https://www.example.com");
    try testing.expectEqual(@as(u32, 222), decoder.table.size);

    const second = try decoder.decode(hex_bytes("4883640effc1c0bf", &buffer), &headers, &storage);
    try expect_header(second[0], ":status", "307");
    try testing.expectEqual(@as(u32, 222), decoder.table.size);

    const third = try decoder.decode(hex_bytes(
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7" ++
            "f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d50" ++
            "07",
        &buffer,
    ), &headers, &storage);
    try testing.expectEqual(@as(usize, 6), third.len);
    try expect_header(third[4], "content-encoding", "gzip");
    try expect_header(
        third[5],
        "set-cookie",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    );
    try testing.expectEqual(@as(u32, 215), decoder.table.size);
}

test "hpack: rejects invalid Huffman coding" {
    var buffer: [16]u8 = undefined;
    var headers: [4]Header = undefined;
    var storage: [64]u8 = undefined;
    var decoder = Decoder{};
    // Value string of four 0xff bytes: 30 bits of ones decode to EOS.
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("008161" ++ "84ffffffff", &buffer), &headers, &storage),
    );
    // 0x00 decodes '0' (5 bits) then leaves 3 zero padding bits — not ones.
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("008161" ++ "8100", &buffer), &headers, &storage),
    );
    // Two 0xff bytes: 16 padding-like bits exceed the 7-bit maximum.
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("008161" ++ "82ffff", &buffer), &headers, &storage),
    );
}

test "hpack: rejects invalid indices and truncated strings" {
    var buffer: [16]u8 = undefined;
    var headers: [4]Header = undefined;
    var storage: [64]u8 = undefined;
    var decoder = Decoder{};
    // Index 0 is never valid for an indexed field.
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("80", &buffer), &headers, &storage),
    );
    // Past the static table with an empty dynamic table.
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("be", &buffer), &headers, &storage),
    );
    // A string promising more bytes than the block holds.
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("00816105686921", &buffer), &headers, &storage),
    );
}

test "hpack: table size updates are validated and positioned" {
    var buffer: [32]u8 = undefined;
    var headers: [4]Header = undefined;
    var storage: [64]u8 = undefined;

    // A shrink evicts; zero clears.
    var decoder = Decoder{};
    _ = try decoder.decode(
        hex_bytes("400a637573746f6d2d6b65790d637573746f6d2d686561646572", &buffer),
        &headers,
        &storage,
    );
    try testing.expectEqual(@as(u32, 1), decoder.table.count);
    _ = try decoder.decode(hex_bytes("2082", &buffer), &headers, &storage);
    try testing.expectEqual(@as(u32, 0), decoder.table.count);
    try testing.expectEqual(@as(u32, 0), decoder.table.size_max);

    // Above the advertised limit.
    decoder = Decoder{};
    decoder.table.size_limit = 256;
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("3fe107", &buffer), &headers, &storage), // update to 1024
    );

    // After a field, or a third update: both refused.
    decoder = Decoder{};
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("8220", &buffer), &headers, &storage),
    );
    decoder = Decoder{};
    try testing.expectError(
        error.Compression,
        decoder.decode(hex_bytes("203f213f22", &buffer), &headers, &storage),
    );
}

test "hpack: an entry larger than the table clears it (RFC 7541 4.4)" {
    var headers: [4]Header = undefined;
    var storage: [256]u8 = undefined;
    var block: [128]u8 = undefined;
    var decoder = Decoder{};
    decoder.table.size_limit = 64;
    decoder.table.size_max = 64;

    // Seed one small entry, then insert one whose size exceeds 64.
    var used: usize = 0;
    used += try encode_field_with_indexing("k", "v", block[used..]);
    used += try encode_field_with_indexing(
        "giant-key",
        "a-value-well-past-sixty-four-bytes-of-entry-size",
        block[used..],
    );
    const decoded = try decoder.decode(block[0..used], &headers, &storage);
    // Both fields are still emitted; the table lost everything.
    try testing.expectEqual(@as(usize, 2), decoded.len);
    try expect_header(decoded[1], "giant-key", "a-value-well-past-sixty-four-bytes-of-entry-size");
    try testing.expectEqual(@as(u32, 0), decoder.table.count);
    try testing.expectEqual(@as(u32, 0), decoder.table.size);
}

test "hpack: bounds trip but the dynamic table stays in sync" {
    var headers: [2]Header = undefined;
    var storage: [256]u8 = undefined;
    var block: [128]u8 = undefined;

    // Three indexed inserts against a 2-slot headers array: the error is
    // TooManyHeaders, yet all three entries must land in the table.
    var used: usize = 0;
    used += try encode_field_with_indexing("a", "1", block[used..]);
    used += try encode_field_with_indexing("b", "2", block[used..]);
    used += try encode_field_with_indexing("c", "3", block[used..]);
    var decoder = Decoder{};
    try testing.expectError(
        error.TooManyHeaders,
        decoder.decode(block[0..used], &headers, &storage),
    );
    try testing.expectEqual(@as(u32, 3), decoder.table.count);
    try expect_header(decoder.table.get(1).?, "c", "3");
    try expect_header(decoder.table.get(3).?, "a", "1");

    // Storage exhaustion reports HeaderListTooLarge, same table guarantee.
    var tiny_storage: [4]u8 = undefined;
    var wide: [4]Header = undefined;
    decoder = Decoder{};
    try testing.expectError(
        error.HeaderListTooLarge,
        decoder.decode(block[0..used], &wide, &tiny_storage),
    );
    try testing.expectEqual(@as(u32, 3), decoder.table.count);
}

test "hpack: encoder forms and round trip" {
    var out: [128]u8 = undefined;
    // Exact static match -> one indexed byte.
    try testing.expectEqual(@as(usize, 1), try encode_header(":method", "GET", &out));
    try testing.expectEqual(@as(u8, 0x82), out[0]);
    try testing.expectEqual(@as(usize, 1), try encode_header(":status", "200", &out));
    try testing.expectEqual(@as(u8, 0x88), out[0]);

    // Static name, literal value; then fully literal — round trip both.
    var used = try encode_header("content-type", "text/plain", &out);
    used += try encode_header("x-custom", "yes", out[used..]);
    var decoder = Decoder{};
    var headers: [4]Header = undefined;
    var storage: [128]u8 = undefined;
    const decoded = try decoder.decode(out[0..used], &headers, &storage);
    try testing.expectEqual(@as(usize, 2), decoded.len);
    try expect_header(decoded[0], "content-type", "text/plain");
    try expect_header(decoded[1], "x-custom", "yes");
    // "Without indexing" never touches the peer's dynamic table.
    try testing.expectEqual(@as(u32, 0), decoder.table.count);

    var small: [2]u8 = undefined;
    try testing.expectError(error.NoSpace, encode_header("x-custom", "yes", &small));
}

/// Test helper: a literal field with incremental indexing, raw strings.
fn encode_field_with_indexing(
    name: []const u8,
    value: []const u8,
    out: []u8,
) error{NoSpace}!usize {
    var used = try write_integer(6, 0x40, 0, out);
    used += try write_string(name, out[used..]);
    used += try write_string(value, out[used..]);
    return used;
}
