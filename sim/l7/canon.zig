//! The canonical L7 wire bytes shared by the scripted origin and the
//! client oracles (§9). Bodies are fixed so the client can detect
//! corruption without correlating connections: the proxy relays body
//! wire bytes verbatim, so the client prefix-checks these raw framed
//! forms against whatever it received.

const std = @import("std");

const assert = std.debug.assert;

pub const sized_body = "canonical-sized-response-body-00";
pub const sized_head = "HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n";
pub const sized_response = sized_head ++ sized_body;
pub const chunked_wire = "10\r\nchunked-body-16b\r\n0\r\n\r\n";
pub const chunked_head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
pub const chunked_response = chunked_head ++ chunked_wire;
pub const until_close_body = "until-close-stream";
pub const until_close_head = "HTTP/1.1 200 OK\r\n\r\n";
pub const until_close_response = until_close_head ++ until_close_body;
pub const truncated_response = sized_head ++ sized_body[0..16];

/// The #175 response-filter edit every proxied response must carry, and
/// the one no response may (its rule matches a class the origin never
/// answers). One definition shared by the harness's rule table and the
/// client's oracle, so the two cannot drift on a spelling.
pub const response_edit_name = "X-Sim-Response";
pub const response_edit_value = "on";
pub const response_never_name = "X-Sim-Never";

/// A parseable head that cannot survive the render: 8190 bytes fits the
/// proxy's 8 KiB response buffer, but no Content-Length and no
/// Transfer-Encoding makes it until-close framing, which forces a
/// Connection: close injection — and 8190 plus that header overflows
/// 8192. Sent at accept time, it races the request legs into the
/// deferred-render path (§7 buffer rotation) and must die as a clean
/// 502 or teardown, never a crash.
pub const oversize_head = "HTTP/1.1 200 OK\r\nx-pad: " ++ ("p" ** 8162) ++ "\r\n\r\n";

comptime {
    assert(sized_body.len == 32);
    assert(chunked_wire[0] == '1' and chunked_wire[1] == '0');
    assert(chunked_wire.len == 4 + 16 + 2 + 5);
    assert(oversize_head.len == 8190);
}
