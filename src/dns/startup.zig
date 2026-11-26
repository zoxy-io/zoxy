//! The first answer for every name a cluster follows (#481), before step
//! zero: asked of the options' own nameservers, in the same wire format
//! (`dns/message.zig`) the resolver asks them in once it serves, so the
//! set a cluster starts with and every set after it come from one source
//! — not the system resolver's hosts file and search domains at startup
//! and the nameservers after.
//!
//! Blocking, and allowed to be: it runs in `App`'s startup sequence
//! (§13), before the loop exists, where reading a certificate blocks
//! too. A name no nameserver answers with an address stops the start
//! (`EndpointNameUnresolved`), as a name the stock binary's front-end
//! cannot resolve does (#480): a cluster must start with somewhere to
//! send traffic.

const std = @import("std");

const constants = @import("../constants.zig");
const Options = @import("../Options.zig");
const dns_endpoints = @import("endpoints.zig");
const dns_host = @import("host.zig");
const message = @import("message.zig");

const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;

pub const Error = error{ EndpointNameUnresolved, OutOfMemory };

/// Datagrams one attempt reads past before it gives up on its reply: a
/// stray reply to an earlier attempt, or a forged one, is read and
/// dropped, and a flood of them ends the attempt as a timeout would.
const stray_replies_max: u32 = 64;

/// `options` with every name a cluster follows that states no addresses
/// resolved: the same options when there is none, or a copy in `arena`
/// that the start then serves. A name `config.resolve` will refuse —
/// not canonical, on port 0 — is left for it to refuse.
pub fn resolveNames(io: std.Io, arena: std.mem.Allocator, options: *const Options) Error!*const Options {
    if (!unresolved(options)) return options;
    // `config.resolve` refuses a cluster that follows names without one.
    const resolver = options.resolver orelse return options;
    const copy = try arena.create(Options);
    copy.* = options.*;
    const clusters = try arena.dupe(Options.Cluster, options.clusters);
    for (clusters) |*cluster| {
        const dns = if (cluster.dns) |*dns| dns else continue;
        const names = try arena.dupe(Options.Cluster.Dns.Name, dns.names);
        for (names) |*name| {
            if (name.addresses.len != 0) continue;
            if (!dns_host.isCanonical(name.host) or name.port == 0) continue;
            name.addresses = try resolveName(io, arena, &resolver, name, dns.addresses_max);
            assert(name.addresses.len >= 1);
        }
        dns.names = names;
    }
    copy.clusters = clusters;
    assert(copy.clusters.len == options.clusters.len);
    return copy;
}

fn unresolved(options: *const Options) bool {
    for (options.clusters) |*cluster| {
        const dns = cluster.dns orelse continue;
        for (dns.names) |*name| {
            if (name.addresses.len == 0) return true;
        }
    }
    return false;
}

/// Every address `name` has in its family, at most `addresses_max` per
/// family, in address order — or the start refused, naming why.
fn resolveName(
    io: std.Io,
    arena: std.mem.Allocator,
    resolver: *const Options.Resolver,
    name: *const Options.Cluster.Dns.Name,
    addresses_max: u16,
) Error![]const IpAddress {
    assert(addresses_max >= 1);
    assert(addresses_max <= constants.dns_addresses_max);
    const types: []const message.RecordType = switch (name.family) {
        .ipv4 => &.{.a},
        .ipv6 => &.{.aaaa},
        .any => &.{ .a, .aaaa },
    };
    var found: std.ArrayList(IpAddress) = .empty;
    var reason: Reason = .no_address;
    for (types) |record_type| {
        var room: [constants.dns_addresses_max]IpAddress = undefined;
        const answer = ask(io, resolver, name, record_type, room[0..addresses_max]);
        const reply = switch (answer) {
            .reply => |reply| reply,
            .failed => |failed| {
                reason = failed;
                continue;
            },
        };
        const addresses = room[0..reply.count];
        dns_endpoints.sortAddresses(addresses);
        for (addresses) |address| {
            const repeated = found.items.len >= 1 and found.items[found.items.len - 1].eql(&address);
            if (!repeated) try found.append(arena, address);
        }
    }
    if (found.items.len == 0) {
        std.debug.print("zoxy: cannot resolve '{s}': {s}\n", .{ name.host, reason.text() });
        return error.EndpointNameUnresolved;
    }
    std.debug.print("zoxy: {s}:{d} is", .{ name.host, name.port });
    for (found.items) |address| std.debug.print(" {f}", .{address});
    std.debug.print("\n", .{});
    return found.items;
}

/// Why a name has no address, as the start's refusal says it.
const Reason = enum {
    no_address,
    nxdomain,
    truncated,
    unanswered,

    fn text(reason: Reason) []const u8 {
        return switch (reason) {
            .no_address => "no address in its family",
            .nxdomain => "no such name (NXDOMAIN)",
            .truncated => "the answer did not fit (TC)",
            .unanswered => "no nameserver answered",
        };
    }
};

const Answer = union(enum) {
    reply: message.Reply,
    failed: Reason,
};

/// One record type of `name`, asked of each nameserver in turn until one
/// answers — as the resolver asks, once it serves.
fn ask(
    io: std.Io,
    resolver: *const Options.Resolver,
    name: *const Options.Cluster.Dns.Name,
    record_type: message.RecordType,
    room: []IpAddress,
) Answer {
    assert(room.len >= 1);
    assert(resolver.nameservers.len >= 1);
    for (resolver.nameservers) |*nameserver| {
        const reply = askOne(io, nameserver, resolver.timeout_ms, name, record_type, room) orelse continue;
        switch (reply.outcome) {
            .answered => return .{ .reply = reply },
            .nxdomain => return .{ .failed = .nxdomain },
            .truncated => return .{ .failed = .truncated },
            // Another nameserver may know.
            .failed => continue,
        }
    }
    return .{ .failed = .unanswered };
}

/// One query to one nameserver over a socket of its own: the reply that
/// proves itself the query's within `timeout_ms`, or null.
fn askOne(
    io: std.Io,
    nameserver: *const IpAddress,
    timeout_ms: u32,
    name: *const Options.Cluster.Dns.Name,
    record_type: message.RecordType,
    room: []IpAddress,
) ?message.Reply {
    assert(nameserver.getPort() != 0);
    assert(timeout_ms >= 1);
    const unspecified: IpAddress = switch (nameserver.*) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    // This box's own failures are named apart from the nameserver's: a
    // socket that will not open is no silence from it.
    const socket = unspecified.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        std.debug.print("zoxy: cannot ask {f} about '{s}': {t}\n", .{ nameserver.*, name.host, err });
        return null;
    };
    defer socket.close(io);
    var id_bytes: [2]u8 = undefined;
    io.random(&id_bytes);
    const id = std.mem.readInt(u16, &id_bytes, .little);
    var query_buffer: [message.query_bytes_max]u8 = undefined;
    const query = message.writeQuery(&query_buffer, id, name.host, record_type);
    socket.send(io, nameserver, query) catch |err| {
        std.debug.print("zoxy: cannot ask {f} about '{s}': {t}\n", .{ nameserver.*, name.host, err });
        return null;
    };
    const deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromMilliseconds(timeout_ms),
        .clock = .awake,
    });
    var buffer: [constants.dns_message_bytes_max + 1]u8 = undefined;
    var strays: u32 = 0;
    while (strays < stray_replies_max) : (strays += 1) {
        const incoming = socket.receiveTimeout(io, &buffer, .{ .deadline = deadline }) catch return null;
        if (incoming.data.len == buffer.len) continue; // Cut: past what a reply may be.
        if (dns_endpoints.orderAddresses(&incoming.from, nameserver) != .eq) continue;
        return message.readReply(incoming.data, id, name.host, record_type, name.port, room) catch continue;
    }
    return null;
}
