//! One HTTP/3 connection (#449): h3's QUIC transport and the HTTP/3
//! session over it, and the TLS handshake carried between the transport
//! and the connection's engine.
//!
//! Sans-I/O, as h2's `Session` is. h3 opens no socket, reads no clock and
//! draws no entropy, and neither does this: a datagram, the time and the
//! connection's identifiers arrive from the endpoint that owns the UDP
//! socket, and what the transport wants sent leaves through it. What is
//! here is what one connection needs and nothing every connection on a
//! socket shares.
//!
//! The handshake is RFC 9001 §4's: no TLS records, one CRYPTO stream per
//! encryption level. Each level's octets go from the transport to the
//! engine (`TlsEngine.quicCrypto`); the engine's flight, its traffic
//! secrets, the client's transport parameters and the handshake's
//! completion come back through a sink into the transport. A refusal on
//! either side closes the connection with the code RFC 9000 names for it,
//! which h3spec reads: TRANSPORT_PARAMETER_ERROR for parameters the client
//! may not send, and the TLS alert's CRYPTO_ERROR for everything the
//! engine refuses. A client's CRYPTO octets past the transport's room are
//! h3's own CRYPTO_BUFFER_EXCEEDED, raised before any of them reach here.

const std = @import("std");
const h3 = @import("h3");

const constants = @import("../../constants.zig");
const TlsEngine = @import("../../tls/Engine.zig");
const crypto = @import("crypto.zig");

const quic = h3.quic;
const assert = std.debug.assert;

/// The connection's shape, from `constants.zig`'s HTTP/3 block (#449).
pub const requests_max = constants.h3_requests_max;
pub const peer_unidirectional_max = constants.h3_peer_unidirectional_max;
/// This side's own unidirectional streams: the control stream and QPACK's
/// two.
pub const own_unidirectional: u32 = h3.http3_server.unidirectional_streams.len;
/// Every stream the transport's table holds at once.
pub const streams_max: u32 = requests_max + peer_unidirectional_max + own_unidirectional;
pub const connection_id_bytes = constants.h3_connection_id_bytes;

/// The QUIC transport, with libcrypto's packet protection (§4).
pub const Quic = quic.Connection(.{
    .crypto = crypto.Backend,
    .streams_max = streams_max,
    .stream_receive_octets = constants.h3_stream_receive_bytes,
    .stream_send_octets = constants.h3_stream_send_bytes,
});

/// HTTP/3 over it. The field section a client may send is held to what one
/// stream's receive buffer can hold whole; past the listener's head buffer
/// it is the 431 the HTTP/1.1 head it becomes would have earned.
pub const Session = h3.Http3Server(Quic, .{
    .requests_max = requests_max,
    .unidirectional_max = peer_unidirectional_max,
    .max_field_section_size = constants.h3_field_section_bytes_max,
});

/// A connection ID, as h3 holds one.
pub const ConnectionId = quic.ConnectionId;
/// What a QUIC close says, and the HTTP/3 codes beside it.
pub const TransportCode = quic.error_code.Transport;
pub const ApplicationCode = quic.error_code.Application;

comptime {
    assert(own_unidirectional == 3);
    assert(connection_id_bytes <= ConnectionId.octets_max);
}

/// The connection pool's element (§5): a transport and its session, laid
/// out once at startup and initialized in place for each connection — at
/// this configuration a slot is the better part of a megabyte, and h3's
/// own rule is that a connection is never a stack value.
pub const Slot = struct {
    pool_next: u32,
    generation: u32,
    quic: Quic,
    session: Session,
    /// The Destination Connection ID of the client's first Initial: what
    /// its Initials carry until it hears this side's, so a retransmitted
    /// one finds this connection rather than starting another.
    original: ConnectionId,
    /// This side's transport parameters, encoded once the transport
    /// exists: what the engine's EncryptedExtensions carries.
    parameters: [Quic.local_transport_parameters_octets_max]u8,
    parameters_len: u16,
    /// Why the handshake's sink refused, recorded before it does: the
    /// engine reports only that the sink refused, and the close code is
    /// the sink's to know.
    refusal: ?TransportCode,

    pub const Start = struct {
        /// The packet that starts the connection: its Destination
        /// Connection ID, which the Initial keys derive from.
        initial_destination: ConnectionId,
        /// What this side asks to be addressed as.
        source: ConnectionId,
        /// The connection began after a Retry, whose token carried the
        /// client's original Destination Connection ID.
        retry: ?Quic.Retried,
        /// RFC 9000 §10.1's idle timeout, advertised as what this side
        /// enforces; zero advertises none.
        idle_timeout_ms: u64,
        /// RFC 9000 §10.3's token for `source`.
        stateless_reset_token: [16]u8,
    };

    /// Begin a connection in this slot, from the Initial that starts it.
    /// Fails on a Retry whose token names the identifier the client is
    /// using now, which no Retry this side minted can, or on transport
    /// parameters past their buffer, which comptime sizes — either way the
    /// slot is the caller's to give back, nothing in it live.
    pub fn begin(slot: *Slot, start: *const Start) (Quic.InitError || error{NoSpaceLeft})!void {
        assert(start.source.bytes().len == connection_id_bytes);
        try slot.quic.initServer(.{
            .initial_destination = start.initial_destination,
            .source = start.source,
            .retry = start.retry,
            .advertised = .{
                .max_idle_timeout_ms = start.idle_timeout_ms,
                .stateless_reset_token = start.stateless_reset_token,
                .disable_active_migration = true,
                .max_streams_bidirectional = requests_max,
                .max_streams_unidirectional = peer_unidirectional_max,
                .streams_opened_max = own_unidirectional,
            },
        });
        slot.session = .init();
        slot.original = if (start.retry) |retried| retried.original_destination else start.initial_destination;
        slot.refusal = null;
        const encoded = slot.quic.localTransportParameters(&slot.parameters) catch return error.NoSpaceLeft;
        slot.parameters_len = @intCast(encoded.len);
        assert(slot.parameters_len >= 1);
        assert(slot.quic.state == .handshaking);
    }

    /// The transport parameters the engine's QUIC config carries.
    pub fn transportParameters(slot: *const Slot) []const u8 {
        assert(slot.parameters_len >= 1);
        assert(slot.parameters_len <= slot.parameters.len);
        return slot.parameters[0..slot.parameters_len];
    }

    /// Carry what the transport received at each level to the engine, and
    /// the engine's answer back. Called after every datagram until the
    /// handshake is confirmed — and after it, since a client's late
    /// CRYPTO octets still have to be read. A refusal closes the
    /// connection; its CONNECTION_CLOSE is the next thing it sends.
    pub fn handshake(slot: *Slot, engine: *TlsEngine) void {
        assert(engine.isQuic());
        const levels = [_]quic.crypto.Level{ .initial, .handshake, .one_rtt };
        for (levels) |level| {
            if (slot.quic.state == .closing or slot.quic.state == .draining) return;
            const available = slot.quic.cryptoOut(level);
            if (available.len == 0) continue;
            const sink = slot.engineSink();
            const taken = engine.quicCrypto(engineLevel(level), available, &sink) catch |err| {
                return slot.quic.close(slot.refusal orelse closeCode(err));
            };
            // All or nothing: none while a ClientHello is still arriving.
            if (taken != 0) assert(taken == available.len);
            slot.quic.cryptoConsumed(level, taken);
        }
    }

    /// Where the engine's output goes: this slot's transport.
    pub fn engineSink(slot: *Slot) TlsEngine.QuicSink {
        return .{
            .ctx = slot,
            .crypto = sinkCrypto,
            .secret = sinkSecret,
            .transportParameters = sinkParameters,
            .connected = sinkConnected,
        };
    }

    fn sinkCrypto(ctx: *anyopaque, level: TlsEngine.QuicLevel, bytes: []const u8) error{QuicSinkRefused}!void {
        const slot: *Slot = @ptrCast(@alignCast(ctx));
        // This side's own flight past the transport's send room: no client
        // sent too much (that is h3's CRYPTO_BUFFER_EXCEEDED, on receipt),
        // so the failure is this side's.
        slot.quic.cryptoIn(transportLevel(level), bytes) catch {
            slot.refusal = .internal_error;
            return error.QuicSinkRefused;
        };
    }

    fn sinkSecret(ctx: *anyopaque, secret: *const TlsEngine.QuicSecret) error{QuicSinkRefused}!void {
        const slot: *Slot = @ptrCast(@alignCast(ctx));
        // The engine derives secrets of its suite's hash length, which h3
        // holds: a refusal here is this side's fault, not the client's.
        const held = quic.crypto.Secret.init(secret.bytes) catch {
            slot.refusal = .internal_error;
            return error.QuicSinkRefused;
        };
        const level = transportLevel(secret.level);
        const suite = suiteOf(secret.suite);
        const installed = switch (secret.direction) {
            .send => slot.quic.installSecret(level, .send, &held, suite),
            .receive => slot.quic.installSecret(level, .receive, &held, suite),
        };
        installed catch {
            slot.refusal = .internal_error;
            return error.QuicSinkRefused;
        };
    }

    fn sinkParameters(ctx: *anyopaque, bytes: []const u8) error{QuicSinkRefused}!void {
        const slot: *Slot = @ptrCast(@alignCast(ctx));
        // RFC 9000 §7.4 and §18.2: a parameter with an invalid value, or
        // one only a server may send, is TRANSPORT_PARAMETER_ERROR.
        slot.quic.transportParametersIn(bytes) catch {
            slot.refusal = .transport_parameter_error;
            return error.QuicSinkRefused;
        };
    }

    fn sinkConnected(ctx: *anyopaque) void {
        const slot: *Slot = @ptrCast(@alignCast(ctx));
        // RFC 9001 §4.1.2: a server's handshake is confirmed once it is
        // complete — the client's Finished verified, which is what the
        // engine reports as connected.
        slot.quic.confirmHandshake();
        // A closing transport confirms nothing; `handshake` feeds the engine
        // only an open one, and nothing in a step closes it.
        if (slot.quic.state == .established) assert(slot.quic.handshakeConfirmed());
    }
};

/// Everything `TlsEngine.quicCrypto` can refuse with.
const EngineError = @typeInfo(@typeInfo(@TypeOf(TlsEngine.quicCrypto)).@"fn".return_type.?).error_union.error_set;

/// The close a refused handshake earns (RFC 9001 §4.8): the alert as
/// CRYPTO_ERROR, or PROTOCOL_VIOLATION. A sink refusal is recorded where it
/// happens (`Slot.refusal`), so one that reaches here unrecorded is this
/// side's own failure.
fn closeCode(err: EngineError) TransportCode {
    const code = switch (err) {
        error.QuicSinkRefused => return .internal_error,
        else => |refused| TlsEngine.quicErrorCode(refused),
    };
    // PROTOCOL_VIOLATION, or CRYPTO_ERROR's range: 0x100 plus an alert.
    if (code != @backingInt(TransportCode.protocol_violation)) {
        assert(code >= 0x100);
        assert(code <= 0x1ff);
    }
    return @fromBackingInt(@as(u62, @intCast(code)));
}

/// zssl's encryption levels are TLS's three; h3's are QUIC's four, 0-RTT's
/// among them, which nothing here ever has keys for.
pub fn transportLevel(level: TlsEngine.QuicLevel) quic.crypto.Level {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .one_rtt,
    };
}

pub fn engineLevel(level: quic.crypto.Level) TlsEngine.QuicLevel {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .one_rtt => .application,
        .zero_rtt => unreachable, // No 0-RTT keys are ever installed (#449).
    };
}

pub fn suiteOf(suite: TlsEngine.QuicCipherSuite) quic.crypto.Suite {
    return switch (suite) {
        .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
        .aes_256_gcm_sha384 => .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
    };
}

test "h3 connection: the levels map both ways, and 0-RTT has no engine level" {
    for (std.enums.values(TlsEngine.QuicLevel)) |level| {
        try std.testing.expectEqual(level, engineLevel(transportLevel(level)));
    }
    try std.testing.expectEqual(quic.crypto.Level.one_rtt, transportLevel(.application));
}
