//! The ALPN vocabulary (RFC 7301, #271): the application protocols a
//! terminating listener may name. Closed, on #180's upgrade-allowlist
//! precedent: a token here is a promise the serving path keeps, never a
//! string handed through to a peer.
//!
//! The config loader validates against it, the engine maps zssl's
//! selection back onto it, and `Server` branches on it — one source, so
//! a token cannot be accepted in one place and unknown in another.

const std = @import("std");

const assert = std.debug.assert;

pub const Protocol = enum(u8) {
    http_1_1,
    /// HTTP/2 over TLS (RFC 9113 §3.2, #275). Spoken by the driver in
    /// `http/h2/Connection.zig`, which refuses every stream until the
    /// exchange runs on one — so it is in the vocabulary, and the engine
    /// may negotiate it, but no config may name it yet (`configurable`).
    h2,

    /// The token on the wire: the IANA "TLS Application-Layer Protocol
    /// Negotiation (ALPN) Protocol IDs" registry spelling.
    pub fn token(protocol: Protocol) []const u8 {
        const bytes = switch (protocol) {
            .http_1_1 => "http/1.1",
            .h2 => "h2",
        };
        assert(bytes.len >= 1);
        assert(bytes.len <= protocol_bytes_max);
        return bytes;
    }

    /// The protocol a token names, or null for one this proxy does not
    /// speak. Exact bytes: RFC 7301 §3.1 compares identifiers as octet
    /// strings, so `HTTP/1.1` is not `http/1.1`.
    pub fn fromToken(bytes: []const u8) ?Protocol {
        for (std.enums.values(Protocol)) |protocol| {
            if (std.mem.eql(u8, bytes, protocol.token())) return protocol;
        }
        return null;
    }

    /// Whether `tls.alpn` may name it. The loader and the schema both ask,
    /// so a protocol the serving path speaks only in part is unknown to an
    /// operator until it is whole: HTTP/2 serves no request yet (#275).
    pub fn configurable(protocol: Protocol) bool {
        return switch (protocol) {
            .http_1_1 => true,
            .h2 => false,
        };
    }
};

/// The most names one offer can carry: each protocol once.
pub const protocols_max: u8 = std.enums.values(Protocol).len;

/// The longest token, which bounds what an offer can put on the wire.
pub const protocol_bytes_max: u8 = 8;

/// What an `http` listener offers when its `tls` block names no list:
/// HTTP/1.1, which is what it has always spoken — now said, rather than
/// left for a client to infer from silence. Static, so every listener
/// can borrow it for the process.
pub const http_default: []const []const u8 = &.{"http/1.1"};

/// Whether `offer` names HTTP/2, so that a connection admitted under it
/// may need a session to speak it with (#275).
pub fn namesH2(offer: []const []const u8) bool {
    assert(offer.len <= protocols_max);
    for (offer) |bytes| {
        if (Protocol.fromToken(bytes).? == .h2) return true;
    }
    return false;
}

/// What a listener offering `offer` says when it has no HTTP/2 session
/// to serve with (#275): the same offer, less `h2` — so a client that
/// would have been refused a session is answered HTTP/1.1 in the
/// handshake rather than turned away after it.
///
/// Static, like `http_default`: the vocabulary is closed at two, so an
/// offer less `h2` is HTTP/1.1 alone or nothing. Nothing is a listener
/// that offers HTTP/2 alone, which has no fallback to give; whether such
/// a listener may exist is the config's to decide when `h2` becomes
/// configurable, and until then `Server` refuses to start one.
pub fn withoutH2(offer: []const []const u8) []const []const u8 {
    if (!namesH2(offer)) return offer;
    comptime assert(protocols_max == 2);
    for (offer) |bytes| {
        if (Protocol.fromToken(bytes).? == .http_1_1) return http_default;
    }
    assert(offer.len == 1);
    return &.{};
}

comptime {
    assert(protocols_max >= 1);
    for (std.enums.values(Protocol)) |protocol| {
        assert(Protocol.fromToken(protocol.token()) == protocol);
    }
    // The default is a list of canonical tokens, not a spelling of its own,
    // and one the loader would accept were it written out.
    for (http_default) |bytes| assert(Protocol.fromToken(bytes).?.configurable());
}

test "alpn: every token names its protocol and nothing else" {
    try std.testing.expectEqual(Protocol.http_1_1, Protocol.fromToken("http/1.1").?);
    try std.testing.expectEqual(Protocol.h2, Protocol.fromToken("h2").?);
    try std.testing.expectEqual(@as(?Protocol, null), Protocol.fromToken("HTTP/1.1"));
    try std.testing.expectEqual(@as(?Protocol, null), Protocol.fromToken("h2c"));
    try std.testing.expectEqual(@as(?Protocol, null), Protocol.fromToken(""));
    try std.testing.expectEqualStrings("http/1.1", http_default[0]);
    try std.testing.expect(!Protocol.h2.configurable());
}

test "alpn: an offer less h2 is HTTP/1.1 alone, or nothing" {
    try std.testing.expect(namesH2(&.{ "h2", "http/1.1" }));
    try std.testing.expect(!namesH2(http_default));
    try std.testing.expect(!namesH2(&.{}));
    // Without h2 in it, the offer is its own fallback — the same slice.
    try std.testing.expectEqual(http_default.ptr, withoutH2(http_default).ptr);
    try std.testing.expectEqual(http_default.ptr, withoutH2(&.{ "h2", "http/1.1" }).ptr);
    try std.testing.expectEqual(http_default.ptr, withoutH2(&.{ "http/1.1", "h2" }).ptr);
    try std.testing.expectEqual(@as(usize, 0), withoutH2(&.{"h2"}).len);
}
