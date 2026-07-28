//! The L7 request scripts (§9), as data: one `Spec` per script names its
//! wire bytes and every oracle bound the client enforces — how many
//! responses a clean seed demands, the most any legal transcript can
//! contain, the exact golden status, the method context for response
//! parsing, and the closed set of statuses an adversarial seed may
//! legally see. Adding a script is adding one enum member and one table
//! entry; the compiler rejects a table with a hole, and the client's
//! comptime checks reject an entry whose bounds contradict each other.

const std = @import("std");

const zoxy = @import("zoxy");

const parser = zoxy.http.parser;

const assert = std.debug.assert;

/// The valid shapes, the §7 reject shapes (each pinned to its exact
/// verdict on clean seeds), and the connection patterns (keep-alive
/// reuse, pipelining, silence).
pub const Script = enum(u8) {
    /// A bodyless GET; expects one canonical 200.
    get,
    /// A POST with a 24-byte sized body; expects one canonical 200.
    post_sized,
    /// A POST with a 6000-byte sized body: bigger than one virtual-socket
    /// push, so the body spans multiple deliveries — the excess-forward
    /// and body-pump paths race the response leg for the head buffer
    /// (§7 buffer rotation), which is where a misbehaving instant origin
    /// meets the deferred render.
    post_big,
    /// A POST with a valid chunked body; expects one canonical 200.
    post_chunked,
    /// A chunked POST whose first body byte violates chunk framing —
    /// the silent-teardown-instead-of-400 shape (§7): clean seeds
    /// demand the 400.
    post_chunked_malformed,
    /// A bare-LF head terminator (smuggling shape); 400.
    malformed_head,
    /// A request line alone overflowing the proxy's 8 KiB head buffer;
    /// 414.
    oversize_uri,
    /// CONNECT is a §1 non-goal; 501.
    connect_method,
    /// Two sequential GETs on one connection: the §5 parking/checkout
    /// path — the second is sent only after the first 200 settles
    /// reusable.
    keepalive_pair,
    /// Two GETs in one send: the proxy answers the first, announces
    /// close (§2), and never serves the second.
    pipelined,
    /// Connects and sends nothing: the head-read deadline reaps it;
    /// any response byte is a violation.
    silent,
    /// A GET whose path only reaches the routable resource after
    /// canonicalization — an encoded `..` that collapses a segment away
    /// (`/deep/%2e%2e/sim` → `/sim`). It must route and forward exactly as
    /// `/sim` would; the origin's canonical oracle catches a raw-path
    /// forward, and a router matching raw bytes would route it elsewhere.
    confusion,
    /// A GET under `/reject`: a §7 filter rejects it with 403 before any
    /// resource is acquired or origin dialed. The golden outcome is exactly
    /// that 403, and the origin must never see the request.
    filter_reject,
    /// A GET under `/edit`: a §7 filter adds a header to the forwarded
    /// request. It routes and succeeds (200); the origin's §7 oracle proves
    /// the edited head still forwards canonical.
    filter_edit,
    /// A GET under `/rewrite`: a §7 filter rewrites the forwarded path to
    /// `/sim`. It routes on the original path and succeeds (200); the
    /// origin sees a canonical rewritten path, never `//`-merged.
    filter_rewrite,
};

/// Everything the client's oracles need to know about one script. The
/// bounds encode §9's tiering: `allowed_statuses` is the adversarial
/// prefix oracle's set, `golden_status`/`expected_responses` the clean
/// seeds' exact demand, `transcript_cap` the walker's surplus bound.
pub const Spec = struct {
    /// The wire bytes sent on connect (empty only for `silent`).
    request: []const u8,
    /// Complete responses a clean seed's exact transcript contains.
    expected_responses: u8,
    /// The most complete responses ANY legal transcript can contain —
    /// one more than `expected_responses` only where adversarial
    /// delivery can legally produce a surplus (see `pipelined`).
    transcript_cap: u8,
    /// The exact status every response of a clean seed must carry.
    /// 0 only when `expected_responses` is 0 (the value is never read).
    golden_status: u16,
    /// The method context for response parsing (HEAD-shaped body rules).
    method: parser.Method,
    /// Statuses a complete response may legally carry under the
    /// adversary. Empty means any complete response is a violation.
    allowed_statuses: []const u16,
    /// Append a second GET once the first response settles reusable —
    /// the §5 parked-connection checkout under schedule fuzz. Such a
    /// script degrades to a single-exchange transcript when its first
    /// response refuses reuse.
    second_request_when_reusable: bool = false,
    /// Clean seeds demand the first response announces close (§2) —
    /// the pipelined shape: the proxy serves the first request and
    /// refuses to look at the second.
    golden_first_announces_close: bool = false,
};

const post_body = "request-body-24-bytes-ab";
pub const get_request = "GET /sim HTTP/1.1\r\nHost: sim\r\n\r\n";
/// Deterministic 6000-byte body for `post_big`, cycled so the
/// origin-side §7 oracle can spot any reordering.
const big_body = blk: {
    @setEvalBranchQuota(30_000);
    var bytes: [6000]u8 = undefined;
    for (&bytes, 0..) |*byte, index| {
        byte.* = 'a' + @as(u8, @intCast(index % 26));
    }
    const frozen = bytes;
    break :blk frozen;
};
comptime {
    assert(post_body.len == 24);
    assert(big_body.len == 6000);
}

/// Valid requests meet the canonical 200, the §8 rungs (503), an
/// upstream the adversary killed (502), or the §8 request-deadline
/// verdict (504) — a mute or stalled origin (adversarial delivery can
/// stall any of them) earns the 504 once the deadline expires with no
/// response byte sent. Clean seeds pin the origin to `sized` and never
/// stall, so `golden_status` still demands exact outcomes there.
const statuses_routed: []const u16 = &.{ 200, 502, 503, 504 };
/// The head routes and forwards before its body is validated, so several
/// outcomes can precede the 400: the §8 rungs, a killed dial, and — the
/// subtlety — an early origin response. An instant origin answers 200
/// before the proxy ever pumps the malformed body (which it then
/// contains, never forwarding it: the origin's §7 oracle still holds).
const statuses_body_reject: []const u16 = &.{ 400, 200, 502, 503, 504 };

const specs = std.enums.EnumArray(Script, Spec).init(.{
    .get = .{
        .request = get_request,
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
    .post_sized = .{
        .request = "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
            "Content-Length: 24\r\n\r\n" ++ post_body,
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .post,
        .allowed_statuses = statuses_routed,
    },
    .post_big = .{
        .request = "POST /big HTTP/1.1\r\nHost: sim\r\n" ++
            "Content-Length: 6000\r\n\r\n" ++ big_body,
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .post,
        .allowed_statuses = statuses_routed,
    },
    .post_chunked = .{
        .request = "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++ "8\r\nabcdefgh\r\n0\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .post,
        .allowed_statuses = statuses_routed,
    },
    .post_chunked_malformed = .{
        // "Z" is no chunk-size digit: the framing violation is in the
        // first body byte, coalesced with the head.
        .request = "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\nZ",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 400,
        .method = .post,
        .allowed_statuses = statuses_body_reject,
    },
    .malformed_head = .{
        // A bare LF terminating the request line (§7 smuggling shape).
        // The parse verdict precedes routing, so no §8 rung or dial
        // failure can precede the 400.
        .request = "GET /sim HTTP/1.1\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 400,
        .method = .get,
        .allowed_statuses = &.{400},
    },
    .oversize_uri = .{
        // The request line alone must overflow the proxy's 8 KiB head
        // buffer with no newline in sight: 414, not 431.
        .request = "GET /" ++ ("a" ** 8500) ++ " HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 414,
        .method = .get,
        .allowed_statuses = &.{414},
    },
    .connect_method = .{
        // The 501 verdict precedes routing. The method context maps to
        // GET: the parser refuses to represent a CONNECT response (the
        // proxy rejects the method before dialing), and the 501 static
        // carries no body either way.
        .request = "CONNECT origin:443 HTTP/1.1\r\nHost: origin\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 501,
        .method = .get,
        .allowed_statuses = &.{501},
    },
    .keepalive_pair = .{
        // The second GET is appended at run time, only after the first
        // 200 settles reusable.
        .request = get_request,
        .expected_responses = 2,
        .transcript_cap = 2,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
        .second_request_when_reusable = true,
    },
    .pipelined = .{
        // The cap admits one more than the clean expectation: when
        // adversarial fragmentation lands exactly on the request
        // boundary, the proxy never observes the pipelined bytes and
        // legally serves both requests as plain keep-alive. The clean
        // tier still pins pipelined to exactly one (detection is
        // deterministic there).
        .request = get_request ++ get_request,
        .expected_responses = 1,
        .transcript_cap = 2,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
        .golden_first_announces_close = true,
    },
    .silent = .{
        // Never produces a response; the zero-response transcript makes
        // the golden status unread.
        .request = "",
        .expected_responses = 0,
        .transcript_cap = 0,
        .golden_status = 0,
        .method = .get,
        .allowed_statuses = &.{},
    },
    .confusion = .{
        // Canonicalizes to /sim (the `/deep` segment is popped by the
        // decoded `..`), so it routes and forwards as /sim.
        .request = "GET /deep/%2e%2e/sim HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
    // §7 filter scripts: a distinct path per action so the listener's
    // rules fire only for these, never the others.
    .filter_reject = .{
        // A reject is answered before any resource is acquired or origin
        // dialed, so no §8 rung or dial failure can precede it — the
        // only complete verdict is the 403.
        .request = "GET /reject HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 403,
        .method = .get,
        .allowed_statuses = &.{403},
    },
    .filter_edit = .{
        // Routes and forwards like a plain GET, so the §8 rungs and a
        // killed dial can precede the 200.
        .request = "GET /edit HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
    .filter_rewrite = .{
        .request = "GET /rewrite HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
});

pub fn spec(script: Script) Spec {
    return specs.get(script);
}

comptime {
    // Per-entry consistency: the clean demand can never exceed the legal
    // cap, an empty request implies a zero-response transcript, a golden
    // status of 0 is exactly the no-response case, and every golden
    // status is a member of its own adversarial set (clean outcomes are
    // legal outcomes).
    for (std.enums.values(Script)) |script| {
        const entry = specs.get(script);
        assert(entry.expected_responses <= entry.transcript_cap);
        assert(entry.transcript_cap <= entry.expected_responses + 1);
        if (entry.request.len == 0) assert(entry.expected_responses == 0);
        if (entry.golden_status == 0) assert(entry.expected_responses == 0);
        if (entry.golden_status != 0) {
            assert(std.mem.indexOfScalar(u16, entry.allowed_statuses, entry.golden_status) != null);
        }
        if (entry.second_request_when_reusable) assert(entry.expected_responses == 2);
        if (entry.golden_first_announces_close) assert(entry.transcript_cap == 2);
    }
}
