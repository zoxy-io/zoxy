//! QUIC packet protection for zoxy's HTTP/3 (#449): h3's connection takes
//! its primitives from a comptime backend, and zoxy's is libcrypto's,
//! through zssl (`src/tls/QuicCrypto.zig`, §4) — in place of h3's
//! `std.crypto` default. Here, where h3 may be imported, is where the two
//! meet: the type h3's `Connection.Config.crypto` names, held to h3's
//! contract by its comptime check and to RFC 9001 appendix A by its
//! conformance suite.

const std = @import("std");
const h3 = @import("h3");

/// The backend every zoxy QUIC connection seals and opens with.
pub const Backend = @import("../../tls/QuicCrypto.zig");

comptime {
    // A drifted signature fails here, naming the declaration, rather than
    // three calls deep inside h3.
    h3.quic.crypto.backend.check(Backend);
}

test "h3 crypto: libcrypto's backend passes h3's conformance suite (RFC 9001 appendix A)" {
    const made = try Backend.ensure();
    defer if (made) Backend.deinit();
    try h3.quic.crypto.conformance.check(Backend);
}
