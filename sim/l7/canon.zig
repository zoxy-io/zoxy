//! The canonical L7 wire bytes shared by the scripted origin and the
//! client oracles (§9). Bodies are fixed so the client can detect
//! corruption without correlating connections: the proxy relays body
//! wire bytes verbatim, so the client prefix-checks these raw framed
//! forms against whatever it received.

const std = @import("std");

const assert = std.debug.assert;

/// The #140 logged headers: a request header two scripts send and a
/// response header the sized origin answers with, plus the one value
/// each may ever carry. The access-log verifier demands that any value
/// appearing under either name is exactly this one — a truncated,
/// corrupted, or stale-from-another-request capture is then a failure
/// under every schedule the adversary produces.
pub const log_request_header = "x-sim-trace";
pub const log_request_value = "sim-trace-1";
pub const log_response_header = "x-sim-origin";
pub const log_response_value = "sized";

/// The hop-by-hop headers the sized origin answers with, and the one it
/// nominates through `Connection` (RFC 9110 §7.6.1, §7). All three must
/// die at this hop: two because they are hop-by-hop by name, the third
/// because the connection option names it.
///
/// They ride the *canonical* response rather than a script of their own so
/// that every seed, every schedule and both populations exercise the strip
/// — and because a response whose headers are all removed leaves the
/// client's bytes exactly as they were, so this costs no other oracle a
/// change. The nominated name is lowercase on the wire and matched
/// case-insensitively, so a proxy that only strips the spelling it was
/// sent still fails.
///
/// The gap this closes was found by measurement, not review: a build that
/// forwarded the origin's response head verbatim — hop-by-hop headers
/// included — passed `zig build ci` in full, 4096 seeds and the live gate,
/// because nothing here had ever sent one.
pub const hop_nominated_header = "x-sim-nominated";
pub const hop_by_hop_lines = "Connection: keep-alive, " ++ hop_nominated_header ++ "\r\n" ++
    "Keep-Alive: timeout=5\r\n" ++
    hop_nominated_header ++ ": dropme\r\n";

pub const sized_body = "canonical-sized-response-body-00";
pub const sized_head = "HTTP/1.1 200 OK\r\nContent-Length: 32\r\n" ++
    log_response_header ++ ": " ++ log_response_value ++ "\r\n" ++
    hop_by_hop_lines ++ "\r\n";
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

/// The #240 hop budget `options_hop` sends, and the one the origin must
/// read. RFC 9110 §7.6.2 has each intermediary forward the received value
/// decremented by one, so these two numbers are the whole property: a
/// proxy that forwarded the header verbatim would show the first, and one
/// that dropped it would show neither.
pub const max_forwards_sent = "3";
pub const max_forwards_forwarded = "2";

/// The Host header the `absolute_form` script sends beside a request
/// line that names a different authority (#233). RFC 9112 §3.2.2 has the
/// authority win, so these bytes must never reach an origin — the origin
/// checks every forwarded head for them, and only that one script can
/// produce them, which makes a global check a precise one.
pub const overridden_host = "overridden.example";

/// The one Location a sim 301 may carry (#176): the harness's redirect
/// rule composes scheme + the request's own host and canonical path,
/// and `filter_redirect` is the only script that earns a 301 — so the
/// client oracle demands this exact value on every one it parses.
pub const redirect_location = "https://sim/redirect";

/// The #178 cookie name a sticky seed's http cluster is keyed on, and
/// the exact tag of the one http endpoint (127.0.0.1:9001). The tag is
/// *pinned* — computed once from `endpointId`'s published formula and
/// frozen here, with the harness asserting the running balancer still
/// mints it at every setup — so the client oracle demands the stamp's
/// bytes the way it demands `redirect_location`'s, and a silent remap
/// of the mint fails the sweep instead of quietly re-homing a fleet.
pub const sticky_cookie_name = "zoxy-sim-srv";
pub const sticky_tag = "b4a7ea22f14bfcac";
/// The whole Set-Cookie value a sticky stamp carries, attributes
/// included — one spelling shared by the oracle so it cannot drift.
pub const sticky_set_cookie_value =
    sticky_cookie_name ++ "=" ++ sticky_tag ++ "; Path=/; HttpOnly";
/// The same stamp on a connection zoxy terminated (#125, #178): there the
/// proxy knows the client-facing scheme is https, so the cookie carries
/// `Secure` and a browser will not hand it back over plaintext. Spelled
/// as the plaintext value plus the attribute rather than as a second
/// literal, so the two cannot drift apart — which is the failure the
/// terminating population's oracle exists to catch, the attribute having
/// shipped missing once already.
pub const sticky_set_cookie_value_secure = sticky_set_cookie_value ++ "; Secure";

/// The #159 configured bodies. `error_page_body` is the harness's page
/// for `403` — the one status a script earns from a filter reject — so
/// every 403 in the sweep must carry exactly these bytes; `respond_body`
/// is what the `/respond` rule answers `200` with. Both are served from
/// immutable memory by the static path, which is what lets the client
/// demand them under every schedule the adversary produces.
pub const error_page_body = "sim-403-page\n";
pub const respond_body = "sim-respond-body\n";
pub const page_content_type = "text/plain";

/// A parseable head that cannot survive the render: 8190 bytes fits the
/// proxy's 8 KiB response buffer, but no Content-Length and no
/// Transfer-Encoding makes it until-close framing, which forces a
/// Connection: close injection — and 8190 plus that header overflows
/// 8192. Sent at accept time, it races the request legs into the
/// deferred-render path (§7 buffer rotation) and must die as a clean
/// 502 or teardown, never a crash.
pub const oversize_head = "HTTP/1.1 200 OK\r\nx-pad: " ++ ("p" ** 8162) ++ "\r\n\r\n";

/// The `101` a WebSocket origin answers an upgrade request with (#180).
/// Carries the participating pair the proxy must let travel: strip
/// either and the client is told it succeeded without being told to
/// what, which is exactly what §7's hop-by-hop exemption exists to stop.
pub const switching_response = "HTTP/1.1 101 Switching Protocols\r\n" ++
    "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

/// The `100 Continue` an Expect-honouring origin answers with (#232),
/// ahead of the response it was going to send anyway. Interim: the
/// exchange is not over, and a proxy that settles on it either closes on
/// a client mid-body or parks an upstream whose real answer is still
/// unread.
pub const interim_continue = "HTTP/1.1 100 Continue\r\n\r\n";

/// `103 Early Hints` with a preload link — what Cloudflare, Fastly and
/// `res.writeEarlyHints` emit. Repeated past `interim_responses_max` it is
/// also the flood the bound exists to cut.
pub const interim_hints = "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n";

comptime {
    // The scans below walk whole heads at comptime; the default quota is
    // spent before the last of them finishes.
    @setEvalBranchQuota(20_000);
    assert(sticky_tag.len == 16);
    assert(sized_body.len == 32);
    // The strip oracle is only as good as what the origin actually sends:
    // pin all three lines here so a tidy-up of `sized_head` that drops one
    // fails the build rather than quietly retiring a check.
    assert(std.mem.indexOf(u8, sized_head, "Connection: keep-alive") != null);
    assert(std.mem.indexOf(u8, sized_head, "Keep-Alive: timeout=5") != null);
    assert(std.mem.indexOf(u8, sized_head, hop_nominated_header ++ ": dropme") != null);
    // The connection option must name the third header, or it is stripped
    // for being unknown rather than for being nominated.
    assert(std.mem.indexOf(u8, sized_head, "keep-alive, " ++ hop_nominated_header) != null);
    assert(chunked_wire[0] == '1' and chunked_wire[1] == '0');
    assert(chunked_wire.len == 4 + 16 + 2 + 5);
    assert(oversize_head.len == 8190);
    // The handshake answer must carry both halves of the pair, or the
    // scenario would pass while proving nothing about the exemption.
    assert(std.mem.indexOf(u8, switching_response, "Upgrade: websocket") != null);
    assert(std.mem.indexOf(u8, switching_response, "Connection: Upgrade") != null);
}
