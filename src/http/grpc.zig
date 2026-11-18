//! gRPC's own request fields (§7, §8): what this proxy reads of a call it
//! otherwise forwards untouched. One of them matters to it: `grpc-timeout`,
//! the client's deadline for the whole call (gRPC over HTTP/2's
//! `Timeout → "grpc-timeout" TimeoutValue TimeoutUnit`). A proxy that
//! ignores it keeps an origin's stream, a relay buffer and an upstream slot
//! working on a call nobody is waiting for any more — so it becomes the
//! exchange's §8 deadline, and its expiry is answered the way a gRPC client
//! reads a deadline: `grpc-status: 4`, DEADLINE_EXCEEDED.
//!
//! Pure functions over the parsed head; the field is still forwarded as the
//! client sent it.

const std = @import("std");

const parser = @import("parser.zig");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// `TimeoutValue` is at most eight ASCII digits.
pub const timeout_digits_max: u32 = 8;

/// Whether the request is a gRPC call: `application/grpc`, alone, with a
/// `+format` suffix, or with parameters (media types compare without case).
/// gRPC-Web (`application/grpc-web…`) is a translation protocol of its own,
/// and not one this proxy speaks.
pub fn isGrpc(content_type: []const u8) bool {
    const media = "application/grpc";
    if (content_type.len < media.len) return false;
    if (!std.ascii.eqlIgnoreCase(content_type[0..media.len], media)) return false;
    if (content_type.len == media.len) return true;
    const next = content_type[media.len];
    return next == '+' or next == ';' or next == ' ' or next == '\t';
}

/// The client's deadline for a gRPC call, in nanoseconds, clamped to what a
/// configured timeout may be (`[1 ms, timeout_ms_max]`) — or null when the
/// request is not a gRPC call, carries no `grpc-timeout`, or carries one
/// that does not parse, which is ignored rather than refused: the call
/// stands, under whatever deadline this proxy would otherwise give it.
pub fn requestTimeoutNs(headers: []const parser.Header) ?u64 {
    const content_type = fieldValue(headers, "content-type") orelse return null;
    if (!isGrpc(content_type)) return null;
    const value = fieldValue(headers, "grpc-timeout") orelse return null;
    const timeout_ns = timeoutNs(value) orelse return null;
    const floor_ns: u64 = std.time.ns_per_ms;
    const ceiling_ns: u64 = @as(u64, constants.timeout_ms_max) * std.time.ns_per_ms;
    const clamped = std.math.clamp(timeout_ns, floor_ns, ceiling_ns);
    assert(clamped >= floor_ns);
    assert(clamped <= ceiling_ns);
    return clamped;
}

/// One `grpc-timeout` value: one to eight digits, then a unit — `H`ours,
/// `M`inutes, `S`econds, `m`illi-, `u` micro- or `n`anoseconds. Saturates
/// rather than wraps: 99999999 hours is past any deadline worth keeping.
pub fn timeoutNs(value: []const u8) ?u64 {
    if (value.len < 2 or value.len > timeout_digits_max + 1) return null;
    const digits = value[0 .. value.len - 1];
    assert(digits.len >= 1 and digits.len <= timeout_digits_max);
    var amount: u64 = 0;
    for (digits) |digit| {
        if (digit < '0' or digit > '9') return null;
        amount = amount * 10 + (digit - '0');
    }
    // Eight digits never overflow the accumulation itself.
    assert(amount < 100_000_000);
    const unit_ns: u64 = switch (value[value.len - 1]) {
        'H' => std.time.ns_per_hour,
        'M' => std.time.ns_per_min,
        'S' => std.time.ns_per_s,
        'm' => std.time.ns_per_ms,
        'u' => std.time.ns_per_us,
        'n' => 1,
        else => return null,
    };
    return std.math.mul(u64, amount, unit_ns) catch std.math.maxInt(u64);
}

/// The first field named `name`, compared without case as field names are.
fn fieldValue(headers: []const parser.Header, name: []const u8) ?[]const u8 {
    assert(name.len >= 1);
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "grpc: a call is application/grpc, alone, with a format or with parameters" {
    try std.testing.expect(isGrpc("application/grpc"));
    try std.testing.expect(isGrpc("application/grpc+proto"));
    try std.testing.expect(isGrpc("Application/GRPC; charset=utf-8"));
    try std.testing.expect(!isGrpc("application/grpc-web"));
    try std.testing.expect(!isGrpc("application/grpc-web+proto"));
    try std.testing.expect(!isGrpc("application/json"));
    try std.testing.expect(!isGrpc("application/grp"));
    try std.testing.expect(!isGrpc(""));
}

test "grpc: grpc-timeout is one to eight digits and a unit, saturating" {
    try std.testing.expectEqual(@as(?u64, 100 * std.time.ns_per_ms), timeoutNs("100m"));
    try std.testing.expectEqual(@as(?u64, 5 * std.time.ns_per_s), timeoutNs("5S"));
    try std.testing.expectEqual(@as(?u64, 2 * std.time.ns_per_min), timeoutNs("2M"));
    try std.testing.expectEqual(@as(?u64, std.time.ns_per_hour), timeoutNs("1H"));
    try std.testing.expectEqual(@as(?u64, 250 * std.time.ns_per_us), timeoutNs("250u"));
    try std.testing.expectEqual(@as(?u64, 7), timeoutNs("7n"));
    try std.testing.expectEqual(@as(?u64, 0), timeoutNs("0n"));
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), timeoutNs("99999999H"));
    // Nine digits, no digits, no unit, an unknown unit, a sign, a space.
    try std.testing.expectEqual(@as(?u64, null), timeoutNs("123456789m"));
    try std.testing.expectEqual(@as(?u64, null), timeoutNs("m"));
    try std.testing.expectEqual(@as(?u64, null), timeoutNs("100"));
    try std.testing.expectEqual(@as(?u64, null), timeoutNs("100s"));
    try std.testing.expectEqual(@as(?u64, null), timeoutNs("-1S"));
    try std.testing.expectEqual(@as(?u64, null), timeoutNs("1 S"));
    try std.testing.expectEqual(@as(?u64, null), timeoutNs(""));
}

test "grpc: a call's deadline is clamped to what a configured timeout may be, and only a call has one" {
    const call = [_]parser.Header{
        .init("Content-Type", "application/grpc"),
        .init("grpc-timeout", "30m"),
    };
    try std.testing.expectEqual(@as(?u64, 30 * std.time.ns_per_ms), requestTimeoutNs(&call));
    const instant = [_]parser.Header{
        .init("content-type", "application/grpc+proto"),
        .init("grpc-timeout", "0n"),
    };
    try std.testing.expectEqual(@as(?u64, std.time.ns_per_ms), requestTimeoutNs(&instant));
    const endless = [_]parser.Header{
        .init("content-type", "application/grpc"),
        .init("grpc-timeout", "99999999H"),
    };
    const ceiling: u64 = @as(u64, constants.timeout_ms_max) * std.time.ns_per_ms;
    try std.testing.expectEqual(@as(?u64, ceiling), requestTimeoutNs(&endless));
    const not_a_call = [_]parser.Header{
        .init("content-type", "application/json"),
        .init("grpc-timeout", "30m"),
    };
    try std.testing.expectEqual(@as(?u64, null), requestTimeoutNs(&not_a_call));
    const malformed = [_]parser.Header{
        .init("content-type", "application/grpc"),
        .init("grpc-timeout", "soon"),
    };
    try std.testing.expectEqual(@as(?u64, null), requestTimeoutNs(&malformed));
}

test "fuzz: grpc-timeout parses to a bounded deadline or to nothing, and never panics" {
    try std.testing.fuzz({}, fuzzTimeout, .{ .corpus = &.{
        "100m",
        "99999999H",
        "0n",
        "123456789S",
        "1x",
    } });
}

fn fuzzTimeout(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [16]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    const input = input_buffer[0..input_len];
    // Accepted exactly when it is one to eight digits and a known unit.
    const parsed = timeoutNs(input);
    const shaped = input.len >= 2 and input.len <= timeout_digits_max + 1 and
        for (input[0 .. input.len - 1]) |byte| {
            if (byte < '0' or byte > '9') break false;
        } else std.mem.indexOfScalar(u8, "HMSmun", input[input.len - 1]) != null;
    assert((parsed != null) == shaped);
    // And as a call's deadline, always inside what a timeout may be.
    const headers = [_]parser.Header{
        .init("content-type", "application/grpc"),
        .init("grpc-timeout", input),
    };
    if (requestTimeoutNs(&headers)) |deadline_ns| {
        assert(parsed != null);
        assert(deadline_ns >= std.time.ns_per_ms);
        assert(deadline_ns <= @as(u64, constants.timeout_ms_max) * std.time.ns_per_ms);
    } else assert(parsed == null);
}
