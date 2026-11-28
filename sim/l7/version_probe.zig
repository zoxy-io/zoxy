//! A datagram in a version the server does not speak, and the Version
//! Negotiation it is owed (RFC 9000 §6, §17.2.1): the probe's connection
//! IDs echoed back swapped, version 1 offered, and no more octets than
//! the probe sent, since an address nothing has validated may not be
//! amplified (§8). The sweep's HTTP/3 clients speak version 1 and never
//! earn one.

const std = @import("std");
const zoxy = @import("zoxy");

const Io = zoxy.Io;
const assert = std.debug.assert;

pub const ProbeError = error{
    /// A clean seed's probe heard nothing back.
    NegotiationUnanswered,
    /// What came back is no Version Negotiation for this probe.
    NegotiationMalformed,
    /// It offered no version 1, or offered the probe's own.
    NegotiationVersionsWrong,
    /// It was longer than the datagram that earned it.
    NegotiationAmplified,
};

/// RFC 9000 §15's reserved pattern: a version nobody speaks.
const probe_version: u32 = 0x0a0a_0a0a;
const quic_v1: u32 = 0x0000_0001;
/// RFC 9000 §14.1: the smallest datagram a server must answer an Initial
/// in, and §6.1's floor for earning a Version Negotiation.
const probe_bytes: u32 = 1200;
const probe_destination: [8]u8 = @splat(0x11);
const probe_source: [8]u8 = @splat(0x22);
/// A long header's layout (RFC 9000 §17.2): the first octet, the version,
/// then each connection ID behind its length octet.
const long_header_bits: u8 = 0xc0;
const version_at: usize = 1;
const first_id_length_at: usize = version_at + 4;
const ids_end: usize = first_id_length_at + 1 + probe_destination.len + 1 + probe_source.len;
/// One octet past the probe: an answer longer than it reads back as longer.
const answer_bytes_max: usize = probe_bytes + 1;

pub fn VersionProbe(comptime IoType: type) type {
    return struct {
        const Self = @This();

        io: *IoType,
        socket: IoType.UdpSocket,
        server: std.Io.net.IpAddress,
        datagram: [probe_bytes]u8,
        send_completion: IoType.DatagramCompletion,
        receive_completion: IoType.DatagramCompletion,
        cancel_completion: IoType.Completion,
        answer: [answer_bytes_max]u8,
        answer_len: u32,
        sending: bool,
        receiving: bool,
        cancelling: bool,
        closed: bool,

        /// Bind, send the probe, and wait for its answer.
        pub fn start(probe: *Self, io: *IoType, server: std.Io.net.IpAddress) !void {
            probe.io = io;
            probe.server = server;
            probe.answer_len = 0;
            probe.send_completion = .{};
            probe.receive_completion = .{};
            probe.cancel_completion = .{};
            probe.cancelling = false;
            probe.closed = false;
            probe.socket = try io.udpBind(.{ .ip4 = .loopback(0) });
            @memset(&probe.datagram, 0);
            // A long header with the Initial type bits, the reserved version,
            // and the two eight-octet connection IDs (§17.2).
            probe.datagram[0] = long_header_bits;
            std.mem.writeInt(u32, probe.datagram[version_at..][0..4], probe_version, .big);
            const second_id_length_at = first_id_length_at + 1 + probe_destination.len;
            probe.datagram[first_id_length_at] = probe_destination.len;
            @memcpy(probe.datagram[first_id_length_at + 1 ..][0..probe_destination.len], &probe_destination);
            probe.datagram[second_id_length_at] = probe_source.len;
            @memcpy(probe.datagram[second_id_length_at + 1 ..][0..probe_source.len], &probe_source);
            assert(second_id_length_at + 1 + probe_source.len == ids_end);
            probe.receiving = true;
            probe.sending = true;
            io.recvFrom(probe.socket, &probe.answer, &probe.receive_completion, Self, probe, onAnswer);
            io.sendTo(probe.socket, &probe.datagram, 0, &probe.server, &probe.send_completion, Self, probe, onSent);
            assert(probe.sending and probe.receiving);
        }

        fn onSent(probe: *Self, result: Io.SendToError!u32) void {
            assert(probe.sending);
            probe.sending = false;
            // A probe that did not go out earns no answer, and `verify` says
            // so where it must: on a clean seed.
            _ = result catch {};
            probe.closeIfIdle();
        }

        fn onAnswer(probe: *Self, result: Io.RecvFromError!Io.Datagram) void {
            assert(probe.receiving);
            probe.receiving = false;
            if (result) |datagram| {
                assert(datagram.len >= 1 and datagram.len <= probe.answer.len);
                probe.answer_len = datagram.len;
            } else |_| {
                // Cancelled, or failed: no answer, which `verify` judges as
                // it judges one that never came.
            }
            probe.closeIfIdle();
        }

        /// The run is over: a receive still out is let go of, and the
        /// socket closes once it is.
        pub fn stop(probe: *Self) void {
            if (probe.closed or !probe.receiving or probe.cancelling) return;
            assert(!probe.closed);
            probe.cancelling = true;
            probe.io.datagramCancel(&probe.receive_completion, &probe.cancel_completion, Self, probe, onCancel);
        }

        fn onCancel(probe: *Self) void {
            assert(probe.cancelling);
            probe.cancelling = false;
            probe.closeIfIdle();
        }

        fn closeIfIdle(probe: *Self) void {
            if (probe.closed or probe.sending or probe.receiving or probe.cancelling) return;
            assert(!probe.sending and !probe.receiving and !probe.cancelling);
            probe.closed = true;
            probe.io.udpClose(probe.socket);
        }

        /// Whether the server's Version Negotiation came back, for the
        /// census; read once `verify` has passed.
        pub fn answered(probe: *const Self) bool {
            assert(probe.answer_len <= probe.answer.len);
            return probe.answer_len >= 1;
        }

        /// The answer, if one came, is this probe's Version Negotiation:
        /// never longer than the probe, and — where the network delivered
        /// it intact, since a corrupted reply cannot be told from a wrong
        /// one — the probe's IDs swapped and the right versions. A clean
        /// seed must hear it.
        pub fn verify(probe: *const Self, clean: bool, intact: bool) ProbeError!void {
            assert(probe.answer_len <= probe.answer.len);
            assert(!clean or intact);
            if (probe.answer_len == 0) return if (clean) error.NegotiationUnanswered else {};
            const answer = probe.answer[0..probe.answer_len];
            if (answer.len > probe.datagram.len) return error.NegotiationAmplified;
            if (!intact) return;
            // Long header, version 0, then the probe's IDs the other way round.
            if (answer.len < ids_end or answer[0] & 0x80 == 0) return error.NegotiationMalformed;
            if (std.mem.readInt(u32, answer[version_at..][0..4], .big) != 0) return error.NegotiationMalformed;
            const first = answer[first_id_length_at..];
            if (first[0] != probe_source.len or !std.mem.eql(u8, first[1..][0..probe_source.len], &probe_source)) {
                return error.NegotiationMalformed;
            }
            const second = first[1 + probe_source.len ..];
            if (second[0] != probe_destination.len) return error.NegotiationMalformed;
            if (!std.mem.eql(u8, second[1..][0..probe_destination.len], &probe_destination)) {
                return error.NegotiationMalformed;
            }
            return verifyVersions(answer[ids_end..]);
        }

        fn verifyVersions(versions: []const u8) ProbeError!void {
            if (versions.len == 0 or versions.len % 4 != 0) return error.NegotiationMalformed;
            assert(versions.len <= answer_bytes_max);
            var offers_v1 = false;
            for (0..@divExact(versions.len, 4)) |index| {
                const version = std.mem.readInt(u32, versions[index * 4 ..][0..4], .big);
                if (version == probe_version) return error.NegotiationVersionsWrong;
                offers_v1 = offers_v1 or version == quic_v1;
            }
            if (!offers_v1) return error.NegotiationVersionsWrong;
        }
    };
}
