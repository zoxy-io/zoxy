//! Scripted nameservers (#481): one zone whose answers move over virtual
//! time, asked over the seam's datagrams by the resolver that follows a
//! cluster's names. Each nameserver answers by its own scripted behaviour —
//! the zone's addresses, an error code, a truncated reply, nothing at all,
//! or a reply under the wrong ID before the right one — so a resolver can be
//! held to what each one costs it. For the resolver's directed tests and the
//! simulator's DNS-following clusters alike. Test support: nothing in the
//! server imports it.

const std = @import("std");

const constants = @import("../constants.zig");
const Io = @import("../io/io.zig");
const message = @import("../dns/message.zig");

const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;

/// How one nameserver answers a query.
pub const Behavior = enum {
    answer,
    servfail,
    nxdomain,
    truncated,
    silent,
    /// A reply under another ID first, then the answer.
    wrong_id_first,
};

/// What the nameservers answer: a run of phases, each the addresses from
/// its instant on, and one behaviour per nameserver.
pub const Zone = struct {
    phases: []const Phase,
    behaviors: []const Behavior,
    /// The simulator's clock when the server started: phases count from it.
    start_ns: u64,
    /// The TTL every answer carries.
    ttl_s: u32,
    queries_seen: u32 = 0,

    pub const Phase = struct {
        from_ns: u64,
        addresses: []const IpAddress,
    };

    fn addressesAt(zone: *const Zone, now_ns: u64) []const IpAddress {
        assert(zone.phases.len >= 1);
        assert(now_ns >= zone.start_ns);
        var current = zone.phases[0].addresses;
        for (zone.phases) |*phase| {
            if (phase.from_ns <= now_ns - zone.start_ns) current = phase.addresses;
        }
        return current;
    }
};

/// The address a `wrong_id_first` nameserver's first, wrong reply names:
/// one no answer should ever let into a cluster's set.
pub const stray_address: IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 66, 0, 66 }, .port = 9000 } };

pub fn Nameserver(comptime IoType: type) type {
    return struct {
        io: *IoType,
        zone: *Zone,
        index: u8,
        socket: IoType.UdpSocket,
        buffer: [IoType.datagram_bytes_max]u8,
        receive: IoType.DatagramCompletion,
        receive_cancel: IoType.Completion,
        receiving: bool,
        stopping: bool,
        closed: bool,
        sends: [8]Send,

        const Self = @This();

        const Send = struct {
            nameserver: *Self,
            bytes: [constants.dns_message_bytes_max]u8,
            completion: IoType.DatagramCompletion,
            armed: bool,
        };

        pub fn start(nameserver: *Self, io: *IoType, zone: *Zone, index: u8, address: IpAddress) !void {
            assert(index < zone.behaviors.len);
            nameserver.* = .{
                .io = io,
                .zone = zone,
                .index = index,
                .socket = try io.udpBind(address),
                .buffer = undefined,
                .receive = .{},
                .receive_cancel = .{},
                .receiving = false,
                .stopping = false,
                .closed = false,
                .sends = undefined,
            };
            for (&nameserver.sends) |*send| {
                send.* = .{ .nameserver = nameserver, .bytes = undefined, .completion = .{}, .armed = false };
            }
            nameserver.armReceive();
        }

        fn armReceive(nameserver: *Self) void {
            assert(!nameserver.receiving);
            nameserver.receiving = true;
            nameserver.io.recvFrom(nameserver.socket, &nameserver.buffer, &nameserver.receive, Self, nameserver, onReceive);
        }

        fn onReceive(nameserver: *Self, result: Io.RecvFromError!Io.Datagram) void {
            assert(nameserver.receiving);
            nameserver.receiving = false;
            const datagram = result catch |err| switch (err) {
                // `stop` cancelled it: close once nothing else is out.
                error.Canceled => {
                    assert(nameserver.stopping);
                    return nameserver.closeIfSettled();
                },
                // A receive the seam failed loses nothing but the query it
                // might have held, which the resolver's timeout answers; a
                // nameserver that stopped listening would be a behaviour
                // no scenario drew.
                else => {
                    if (nameserver.stopping) return nameserver.closeIfSettled();
                    return nameserver.armReceive();
                },
            };
            if (nameserver.stopping) return nameserver.closeIfSettled();
            nameserver.answer(nameserver.buffer[0..datagram.len], &datagram.peer);
            nameserver.armReceive();
        }

        fn answer(nameserver: *Self, bytes: []const u8, peer: *const IpAddress) void {
            const question = message.readQuery(bytes) orelse return;
            const zone = nameserver.zone;
            zone.queries_seen += 1;
            const addresses = zone.addressesAt(nameserver.io.nowNs());
            switch (zone.behaviors[nameserver.index]) {
                .silent => {},
                .answer => nameserver.reply(&question, &.{ .addresses = addresses, .ttl_s = zone.ttl_s }, peer),
                .servfail => nameserver.reply(&question, &.{ .rcode = 2 }, peer),
                .nxdomain => nameserver.reply(&question, &.{ .rcode = 3 }, peer),
                .truncated => nameserver.reply(&question, &.{ .truncated = true, .addresses = addresses }, peer),
                .wrong_id_first => {
                    nameserver.reply(&question, &.{ .addresses = &.{stray_address}, .id = question.id +% 1 }, peer);
                    nameserver.reply(&question, &.{ .addresses = addresses, .ttl_s = zone.ttl_s }, peer);
                },
            }
        }

        fn reply(nameserver: *Self, question: *const message.Question, script: *const message.Answer, peer: *const IpAddress) void {
            // A nameserver with every send out drops the query, as a busy one
            // would; the resolver's timeout is what answers that.
            const send = for (&nameserver.sends) |*send| {
                if (!send.armed) break send;
            } else return;
            const bytes = message.writeReply(&send.bytes, question, script);
            send.armed = true;
            nameserver.io.sendTo(nameserver.socket, bytes, 0, peer, &send.completion, Send, send, onSend);
        }

        fn onSend(send: *Send, result: Io.SendToError!u32) void {
            // A reply the network lost is the resolver's timeout to answer.
            _ = result catch {};
            assert(send.armed);
            send.armed = false;
            send.nameserver.closeIfSettled();
        }

        /// Stop answering, and close once nothing is armed on the socket.
        pub fn stop(nameserver: *Self) void {
            if (nameserver.stopping) return;
            nameserver.stopping = true;
            if (nameserver.receiving) {
                nameserver.io.datagramCancel(&nameserver.receive, &nameserver.receive_cancel, Self, nameserver, onCanceled);
            }
            nameserver.closeIfSettled();
        }

        fn onCanceled(nameserver: *Self) void {
            assert(nameserver.stopping);
            nameserver.closeIfSettled();
        }

        fn closeIfSettled(nameserver: *Self) void {
            if (!nameserver.stopping or nameserver.closed) return;
            if (nameserver.receiving) return;
            for (&nameserver.sends) |*send| {
                if (send.armed) return;
            }
            nameserver.closed = true;
            nameserver.io.udpClose(nameserver.socket);
            assert(nameserver.closed);
        }
    };
}
