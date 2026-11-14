//! The ALPN vocabulary (RFC 7301, #271): the application protocols a
//! terminating listener may name. Closed, on #180's upgrade-allowlist
//! precedent: a token here is a promise the serving path keeps, never a
//! string handed through to a peer. HTTP/1.1 is all this proxy speaks
//! today, so it is all this names; `h2` joins with #275.
//!
//! The config loader validates against it, the engine maps zssl's
//! selection back onto it, and `Server` branches on it — one source, so
//! a token cannot be accepted in one place and unknown in another.

const std = @import("std");

const assert = std.debug.assert;

pub const Protocol = enum(u8) {
    http_1_1,

    /// The token on the wire: the IANA "TLS Application-Layer Protocol
    /// Negotiation (ALPN) Protocol IDs" registry spelling.
    pub fn token(protocol: Protocol) []const u8 {
        const bytes = switch (protocol) {
            .http_1_1 => "http/1.1",
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

comptime {
    assert(protocols_max >= 1);
    for (std.enums.values(Protocol)) |protocol| {
        assert(Protocol.fromToken(protocol.token()) == protocol);
    }
    // The default is a list of canonical tokens, not a spelling of its own.
    for (http_default) |bytes| assert(Protocol.fromToken(bytes) != null);
}

test "alpn: every token names its protocol and nothing else" {
    try std.testing.expectEqual(Protocol.http_1_1, Protocol.fromToken("http/1.1").?);
    try std.testing.expectEqual(@as(?Protocol, null), Protocol.fromToken("HTTP/1.1"));
    try std.testing.expectEqual(@as(?Protocol, null), Protocol.fromToken("h2"));
    try std.testing.expectEqual(@as(?Protocol, null), Protocol.fromToken(""));
    try std.testing.expectEqualStrings("http/1.1", http_default[0]);
}
