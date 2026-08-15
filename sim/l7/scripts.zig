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

const canon = @import("canon.zig");
const constants = zoxy.constants;
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
    /// close (§7), and never serves the second.
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
    /// A GET under `/redirect`: a §7 filter answers 301 with a Location
    /// composed from the request's own host and path (#176), before any
    /// resource is acquired or origin dialed — `filter_reject`'s shape
    /// with the one response this proxy renders per request instead of
    /// serving from static memory.
    filter_redirect,
    /// A GET under `/respond`: a §7 filter answers `200` from a
    /// configured body (#159) — this proxy as the origin. Timed like
    /// `filter_reject`: answered before any post-parse resource is
    /// acquired or origin dialed. The client demands the exact body,
    /// and — because a configured page is a static — that it carries
    /// *neither* response-side stamp, which is how the sweep proves
    /// from outside that a page bypasses the response render.
    filter_respond,
    /// A GET under `/edit`: a §7 filter adds a header to the forwarded
    /// request. It routes and succeeds (200); the origin's §7 oracle proves
    /// the edited head still forwards canonical.
    filter_edit,
    /// A GET under `/rewrite`: a §7 filter rewrites the forwarded path to
    /// `/sim`. It routes on the original path and succeeds (200); the
    /// origin sees a canonical rewritten path, never `//`-merged.
    filter_rewrite,
    /// A GET carrying an inbound `X-Forwarded-For` chain, spread over two
    /// header lines of which the second is already a chain itself (§7).
    /// The listener's drawn mode decides what the origin sees: `append`
    /// joins all three hops ahead of the peer it observed, `replace`
    /// discards them, and forwarding off passes both lines through
    /// untouched. Without a script sending one, `append` and `replace`
    /// render identical bytes and drawing the mode proves nothing about
    /// either — the join and the render's suppression of inbound copies
    /// are reachable only from here.
    forwarded_inbound,
    /// The same shape with a chain past `forwarded_chain_bytes_max`,
    /// which an `append` listener must drop *whole* rather than truncate
    /// (§7). Only seeds that drew `append` reach the rung, and
    /// `forwarded_chain_dropped` witnesses it.
    forwarded_oversize,
    /// A GET carrying the pinned #178 tag of the one http endpoint. On
    /// a sticky seed it is *followed* — the client oracle demands the
    /// response carry no re-stamp, the idempotence half — and
    /// `l7_sticky_followed` fires. On any other seed the cookie is
    /// inert bytes the origin sees verbatim.
    sticky_follow,
    /// A GET carrying a well-formed tag (the minted grammar) that names
    /// no endpoint of any cluster. Served like any GET; on a sticky
    /// seed the response must re-announce (`l7_sticky_repicked`) — the
    /// forged-cookie / shrunk-config shape.
    sticky_repick,
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
    /// Clean seeds demand the first response announces close (§7) —
    /// the pipelined shape: the proxy serves the first request and
    /// refuses to look at the second.
    golden_first_announces_close: bool = false,
    /// This script's 200 is answered from a configured page (#159) rather
    /// than proxied, so it crosses neither response-side render — no #175
    /// stamp, no #178 cookie — and its body is the page's, byte for byte.
    /// A property of the request's path, which only the table knows: 403
    /// pages are blanket by status, but a 200 from memory is
    /// indistinguishable from a proxied one without this.
    respond_page: bool = false,
    /// The request already names an endpoint in the #178 grammar, so its
    /// proxied 200 owes *no* re-stamp — idempotence is the contract.
    /// Every other routed request is assigned or repicked and owes the
    /// pinned cookie.
    sticky_request_pinned: bool = false,
};

const post_body = "request-body-24-bytes-ab";
/// The #140 trace header, on the two scripts that carry one: enough for
/// the access-log verifier to see captured values under every schedule
/// the adversary produces. The scripts that omit it are not an
/// absent-case oracle — one canonical value is shared by every sender,
/// so a stale capture bleeding it into a line that should carry none is
/// indistinguishable from a fresh one here. That regression is the
/// directed tests' (`http_proxy_test.zig` chains two connections
/// through one pool slot); what the sweep adds is that no *other* value
/// can ever appear.
const trace_line = canon.log_request_header ++ ": " ++ canon.log_request_value ++ "\r\n";
pub const get_request = "GET /sim HTTP/1.1\r\nHost: sim\r\n" ++ trace_line ++ "\r\n";
/// The same request with an explicit close, for a caller that has no
/// script driving it and needs the exchange to end the connection: the
/// §4 terminating population sends one request and is done, so a
/// kept-alive connection would leave it waiting on a peer with nothing
/// left to say.
pub const get_request_close = "GET /sim HTTP/1.1\r\nHost: sim\r\nConnection: close\r\n" ++
    trace_line ++ "\r\n";
/// A keep-alive POST for the same caller (#204): the request-body leg,
/// which a GET cannot reach, on a connection the exchange leaves open so
/// a second request can follow it. Byte-identical to `post_sized`'s
/// request, so the origin's §7 oracle judges it by the rule it already
/// has rather than by a second spelling of the same thing.
pub const post_request = "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++ trace_line ++
    "Content-Length: 24\r\n\r\n" ++ post_body;
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

/// The two `X-Forwarded-For` lines `forwarded_inbound` sends — the second
/// already comma-joined, so the §7 join is exercised both across lines
/// and within one. The head is built from these rather than from a second
/// copy of the same bytes, so the bound asserted below is a check on what
/// is actually sent instead of one that would keep passing after an edit.
const forwarded_inbound_lines = [_][]const u8{ "1.1.1.1", "2.2.2.2, 3.3.3.3" };

/// An inbound chain small enough that every mode carries it whole.
const forwarded_inbound_head = "GET /sim HTTP/1.1\r\nHost: sim\r\n" ++
    "X-Forwarded-For: " ++ forwarded_inbound_lines[0] ++ "\r\n" ++
    "X-Forwarded-For: " ++ forwarded_inbound_lines[1] ++ "\r\n\r\n";

/// One line of the oversize chain: hops enough to reach three quarters of
/// the §7 chain bound, so a single line fits and two cannot. Built from
/// the constant rather than a literal, so raising the bound keeps the
/// script oversize instead of silently making it a second `get`.
const forwarded_oversize_line = blk: {
    const hop = "10.11.12.13";
    const target = @divFloor(@as(usize, constants.forwarded_chain_bytes_max) * 3, 4);
    var chain: []const u8 = hop;
    while (chain.len + 2 + hop.len <= target) chain = chain ++ ", " ++ hop;
    const frozen = chain;
    break :blk frozen;
};

const forwarded_oversize_head = "GET /sim HTTP/1.1\r\nHost: sim\r\n" ++
    "X-Forwarded-For: " ++ forwarded_oversize_line ++ "\r\n" ++
    "X-Forwarded-For: " ++ forwarded_oversize_line ++ "\r\n\r\n";

comptime {
    // The inbound chain fits, so no mode drops it — this script proves
    // the join, never the bound. Joined as `appendInboundChain` joins it:
    // the lines in order, separated by ", ".
    assert(forwarded_inbound_lines[0].len + 2 + forwarded_inbound_lines[1].len <=
        constants.forwarded_chain_bytes_max);
    // One oversize line fits the bound and two cannot, so the drop is
    // reached only after the first line has already been joined — the
    // accumulating path, not a single header oversize on its own.
    assert(forwarded_oversize_line.len <= constants.forwarded_chain_bytes_max);
    assert(2 * forwarded_oversize_line.len + 2 > constants.forwarded_chain_bytes_max);
    // Both heads must reach the origin as heads, not as 414/431 verdicts:
    // the proxy's own cap is the ceiling either way.
    assert(forwarded_inbound_head.len < constants.head_buffer_bytes_default);
    assert(forwarded_oversize_head.len < constants.head_buffer_bytes_default);
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
        .request = post_request,
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
        // The parse verdict precedes routing, so no post-parse rung or
        // dial failure can precede the 400 — but the §5 head ring gates
        // the read *before* the parse, so its 503 can.
        .request = "GET /sim HTTP/1.1\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 400,
        .method = .get,
        .allowed_statuses = &.{ 400, 503 },
    },
    .oversize_uri = .{
        // The request line alone must overflow the proxy's 8 KiB head
        // buffer with no newline in sight: 414, not 431. The §5 head
        // ring gates the read before any byte accumulates, so its 503
        // can precede the verdict.
        .request = "GET /" ++ ("a" ** 8500) ++ " HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 414,
        .method = .get,
        .allowed_statuses = &.{ 414, 503 },
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
        // Only the §5 head ring's 503 precedes the parse the 501 rides on.
        .allowed_statuses = &.{ 501, 503 },
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
        // A reject is answered before any post-parse resource is
        // acquired or origin dialed, so no such rung or dial failure can
        // precede it — but the request must first be *read*, and the §5
        // head ring gates that: its 503 is the one verdict that can
        // arrive instead.
        .request = "GET /reject HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 403,
        .method = .get,
        .allowed_statuses = &.{ 403, 503 },
    },
    .filter_redirect = .{
        // `filter_reject`'s timing exactly — answered before any
        // post-parse resource — so the same one preemption applies: the
        // §5 head ring's 503. The 301's Location is asserted by the
        // client's own walk (#176), composed from this request's host
        // and path.
        .request = "GET /redirect HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 301,
        .method = .get,
        .allowed_statuses = &.{ 301, 503 },
    },
    .filter_respond = .{
        // `filter_reject`'s timing exactly — the answer precedes every
        // post-parse resource — so the §5 head ring's 503 is again the
        // one verdict that can arrive instead.
        .request = "GET /respond HTTP/1.1\r\nHost: sim\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = &.{ 200, 503 },
        .respond_page = true,
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
    // §7 client-address forwarding: both route and forward like a plain
    // GET, so the §8 rungs and a killed dial can precede the 200. What
    // they change is what the *origin* is told, which the client cannot
    // see. What they buy is reach, not verdicts: the assembly runs under
    // the adversarial schedule, and the origin's oracle holds it to a
    // head that parses. Which hops survived and in what order is pinned
    // by the directed tests in src/http_proxy_test.zig, not here — a join
    // bug that stayed well-formed would pass this seed and fail those.
    .forwarded_inbound = .{
        .request = forwarded_inbound_head,
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
    .forwarded_oversize = .{
        .request = forwarded_oversize_head,
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
    // #178: both route and forward like a plain GET, so the §8 rungs and
    // a killed dial can precede the 200. What they change is the sticky
    // verdict, which the client's stamp oracle reads off every response
    // head — and on non-sticky seeds they degrade to `get` with inert
    // cookie bytes, which is itself worth sweeping (a cookie must never
    // do anything on a cluster that is not keyed on it).
    .sticky_follow = .{
        .request = "GET /sim HTTP/1.1\r\nHost: sim\r\n" ++
            "Cookie: " ++ canon.sticky_cookie_name ++ "=" ++ canon.sticky_tag ++ "\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
        .sticky_request_pinned = true,
    },
    .sticky_repick = .{
        .request = "GET /sim HTTP/1.1\r\nHost: sim\r\n" ++
            "Cookie: " ++ canon.sticky_cookie_name ++ "=ffffffffffffffff\r\n\r\n",
        .expected_responses = 1,
        .transcript_cap = 1,
        .golden_status = 200,
        .method = .get,
        .allowed_statuses = statuses_routed,
    },
});

/// The §4 terminating population's transcript (#215): the fixed
/// POST-then-close-GET pair the harness sends over a terminated
/// listener, described so the plaintext response oracle can judge those
/// responses too. Both requests are the ones the table already holds —
/// `post_request` is `post_sized`'s bytes and the follow-up is `get`'s
/// with an explicit close — so what comes back owes exactly what a
/// plaintext client's would.
///
/// A `Spec` and not a `Script`, deliberately: the plaintext population
/// draws its script with `enumValue`, so a member added for a population
/// that never draws would re-roll every seed's script and take the §9
/// census margins with it. This population sends its pair.
///
/// The method is the first request's. It reaches the parser only as the
/// HEAD-shaped body rule, which POST and GET share, so one context is
/// right for both responses.
pub const terminating_pair: Spec = .{
    .request = post_request,
    .expected_responses = 2,
    .transcript_cap = 2,
    .golden_status = 200,
    .method = .post,
    .allowed_statuses = statuses_routed,
};

comptime {
    // The pair is the two requests the harness actually sends, and the
    // oracle reads the first one's spelling from here.
    assert(std.mem.eql(u8, terminating_pair.request, post_request));
    assert(terminating_pair.expected_responses == terminating_pair.transcript_cap);
    assert(!terminating_pair.respond_page);
    assert(!terminating_pair.sticky_request_pinned);
}

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
        // A page is answered from memory, so its script can only ever see
        // the one status the page carries — and a pinned request is one
        // that routes, which a page never does.
        if (entry.respond_page) assert(entry.golden_status == 200);
        if (entry.respond_page) assert(!entry.sticky_request_pinned);
    }
}
