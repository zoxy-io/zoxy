//! The serving-path functions `sim_gap.zig` sets apart from the sweep's
//! gap (§9, #487): each with the most lines it may excuse and the reason
//! the gate's sweep does not reach them — what keeps it away, and what
//! reaches the lines instead. The unit tests reach every one (that is
//! what puts a line in the report at all). The report fails when an
//! excused function's gap outgrows its entry, so a change that opens a
//! new gap there is judged rather than absorbed, and names an entry whose
//! function the sweep reaches whole, so a widened scenario deletes it.
//!
//! The reasons are kinds, below, and an entry names one. A `_part` kind
//! is the same reason for a function a longer sweep reaches some of.

comptime {
    @setEvalBranchQuota(4 * exemptions.len * exemptions.len);
    for (exemptions, 0..) |exemption, index| {
        // Each entry excuses something, says why, and names a function
        // no other entry does: a duplicate would never match.
        if (exemption.lines == 0) @compileError("an exemption excusing no line");
        if (exemption.reason.len == 0) @compileError("an exemption without a reason");
        for (exemptions[index + 1 ..]) |other| {
            if (std.mem.eql(u8, exemption.path, other.path) and std.mem.eql(u8, exemption.owner, other.owner)) {
                @compileError("two exemptions name " ++ exemption.path ++ ":" ++ exemption.owner);
            }
        }
    }
}

const std = @import("std");

/// One function's excused lines, and why. `lines` is a ceiling: the larger
/// of what arm64's and x86_64's kcov count there.
pub const Exemption = struct {
    path: []const u8,
    owner: []const u8,
    lines: u16,
    reason: []const u8,
};

const watchdog_off = "the serving watchdog is off for the sweep (`loop_watchdog_ms = null`): a tick every " ++
    "second of virtual time would move every schedule; server_test.zig provokes it";
const watchdog = "the serving watchdog's configuration, which no seed states (`loop_watchdog_ms = null`); " ++
    "config.zig's tests resolve it";

const rare = "a schedule the gate's 4096 seeds do not draw: a sweep of seeds 1..65536 reaches every " ++
    "line here (kcov, measured for #487), and the nightly's blocks draw it";
const partly_rare = "; some of these lines are a schedule the gate's seeds do not draw, which seeds " ++
    "1..65536 reach";
const schedule_part = "a teardown, completion or deadline order the gate's seeds do not draw — a " ++
    "resource still held when its connection ends, a late completion, a budget that expires " ++
    "mid-leg — some of which seeds 1..65536 reach; the module's directed tests order them";

const extension = "extension machinery (#417, #425, #435, #436, #437) a build's own extensions " ++
    "drive and the sim's scripted ones do not: connection and route policies on an SNI route, " ++
    "pick completion, a policy's edits refused, a consult refused, endpoint-set lookups, " ++
    "extension metrics over families the sim registers none of, and branches compiled for an " ++
    "extension set other than the sim's; src/extension_test.zig, http_proxy_test.zig and " ++
    "examples/edge drive it";
const census = "a shed or refusal rung whose counter the census exempts (sim/main.zig): no pool " ++
    "size, head or route table the sweep draws reaches it, and the exemption names the directed " ++
    "test that does";
const config_shape = "configuration no seed states, resolved or acted on here: listener ALPN " ++
    "lists, two QUIC binds, response header edits by add or remove, a literal redirect target, " ++
    "a health check's host, error pages and log headers past one, a route table whose order " ++
    "only a tie or a header predicate decides, weights that leave an endpoint unreachable, " ++
    "ramped caps, a deep `rewrite_prefix`, response status lists that match; config.zig's " ++
    "and the module's tests resolve it";
const unix = "a Unix-socket listener or endpoint (#303), which no seed binds or dials: no client " ++
    "address to log, filter or forward, a socket path to resolve, render or key on; " ++
    "server_test.zig and http_proxy_test.zig's unix scenarios drive it";
const startup = "startup's price (§5) and its parsing: budget.zig and the loader size and read the " ++
    "config with it before Server.init, and the sim builds its pools and names in code";
const comptime_only = "compile-time arithmetic: run by `comptime` asserts and startup's price, never " ++
    "by a running server";
const test_support = "test support beside the code it serves — a fixture, a builder, a fuzz source, " ++
    "a test address or peer — that the caller count takes for serving code by a name it shares";

const h2_peer = "an HTTP/2 peer doing what the sweep's never do — a header block past one " ++
    "frame, a SETTINGS change once streams are open, a peer's push of credit, a stream or " ++
    "connection error other than the seven its violators and the floods commit: its origin " ++
    "refuses, resets and drains, but its adversary acts on delivery, never on frames; " ++
    "src/http/h2's tests and h2spec drive it";
const h2_request = "an HTTP/2 request the sweep's clients never make — refused before its head " ++
    "maps, an asterisk-form OPTIONS, or a `:path` in neither form §8.3.1 allows; they ask " ++
    "`get`'s, `consult_get`'s, the handler's and POST paths, all origin-form; " ++
    "http_proxy_test.zig and downgrade's tests drive it";
const h2_tls = "HTTP/2 over a terminating TLS listener (ALPN `h2`): the sweep's TLS clients speak " ++
    "HTTP/1.1 and its HTTP/2 clients h2c, and a listener offered `h2` alone refuses it (#271); " ++
    "server_test.zig's h2 TLS scenarios drive it";
const h2_origin_tls = "TLS to an HTTP/2 origin failing: the sweep's h2 origin serves the chain its " ++
    "cluster trusts over a byte-faithful TCP adversary; http_proxy_test.zig's h2 origin " ++
    "scenarios refuse a chain";
const origin_answer = "an origin answer the sweep's scripted origins never give — bytes past a " ++
    "declared length, a `101` to a request that asked no upgrade, a malformed head under a " ++
    "borrowed scratch, an HTTP/2 origin's 304 or HEAD answer, nominated `te`, or asterisk " ++
    "target: they answer the canonical sized, chunked and trailered 200s, the HTTP/2 one " ++
    "behind an interim too, and the no-content path's 204; http_proxy_test.zig drives it";
const grpc_service = "a `grpc` check naming a service: the sweep's ask about the server as a " ++
    "whole (`service = \"\"`); origin_pool's tests compose a named one";
const grpc_timeout = "a `grpc-timeout` in hours, minutes or seconds, or a gRPC content type with " ++
    "parameters: the sweep's calls send `5m` and a bare `application/grpc`; grpc.zig's tests " ++
    "and its fuzz target drive the rest";
const h3_peer = "a QUIC or HTTP/3 peer the sweep's clients never are — one whose request is " ++
    "refused or capped mid-connection; its violators break three rules and its probe offers a " ++
    "version the server does not speak, but no other; src/http/h3's tests and h3spec drive it";
const head_shape = "a request or response head no script, client or origin sends — percent-escapes, " ++
    "dot segments, chunk extensions or a malformed size line, an obsolete, repeated or escaped " ++
    "field, an asterisk target, a chunked body to a handler, a host-less redirect, a target past " ++
    "the access log's room; src/http's parser tests and the fuzz targets drive it";
const tls_shape = "a TLS shape the sweep's clients never take — a client chain past one leaf, a " ++
    "client certificate's names past what fits or forwarded to a policy, a record an engine is " ++
    "fed in pieces past what a session sends, a ticket that does not open, an RSA key beside a " ++
    "mismatched leaf, an empty server name; src/tls's tests drive it";
const origin_tls = "TLS to an HTTPS origin failing mid-session: the sweep's HTTPS origin serves " ++
    "its chain over a byte-faithful TCP adversary, and a hangup mid-handshake reaches the " ++
    "counter (a census rate) more often than these legs; upstream_tls's tests drive them";
const hello_shape = "a ClientHello shape the sweep's L4 clients never send — a server-name list " ++
    "with more than one entry, an extension block that fails mid-vector; client_hello's tests " ++
    "and its fuzz target drive it";
const proxy_header = "a PROXY header shape the sweep's clients never send — v2 UNSPEC or UNIX, a " ++
    "v1 line that fails past its first token, bytes past the header in one delivery on a listener " ++
    "that also peeks a hello; proxy_protocol's tests and fuzz target drive it";
const dns_shape = "a nameserver reply the scripted zone never writes — CNAME chains, compressed " ++
    "names, AAAA answers, more records than fit, a set whose duplicates merge; src/dns's tests " ++
    "drive it";
const health_shape = "a health check the sweep never states — an HTTP check naming its own host, " ++
    "a build's check kind past its rounds, a probe that sends in pieces; health's tests drive it";
const log_sink = "an access-log file sink, reopened on a signal or failing to write: the sweep " ++
    "logs to stdout through the seam, and its writes land; access_log's tests drive it";
const signal = "a signal past SIGTERM — SIGHUP's log reopen — which the sweep never sends; " ++
    "server_test.zig and the live gate do";
const tunnel_drain = "a drain stated with no deadline that meets an upgraded tunnel still open: " ++
    "no seed of 1..65536 combines the two; server_test.zig's drain scenarios drive the tunnel's " ++
    "own deadline";
const balance_shape = "a balancing input the sweep's clusters never present — a hash keyed " ++
    "on a header's or cookie's bytes, a tier below the lowest, a health-steered pick past what " ++
    "two endpoints decide, a cap no endpoint is under, a panic that narrows; balancer's tests " ++
    "drive it";
const kcov_line = "a statement the sweep does run that kcov reports unrun: its instructions land " ++
    "on the lines around it — an argument line of the gRPC probe's call, an assert folded into " ++
    "the check that precedes it, an `inline for` header whose body is unrolled";
const kcov_line_x86 = "a statement the sweep runs on every architecture — arm64's kcov sees it " ++
    "run, and a seed's schedule is the same on both — that x86_64's kcov reports unrun, its " ++
    "instructions attributed to the lines around it";
const test_teardown = "freeing the QUIC cipher contexts, which only tests do: a process keeps them " ++
    "for its life";
const pump_policy = "the pump's own `sendSlice`, compiled only for a policy that brings none: the " ++
    "relay's and the proxy's each bring theirs, so only pump_transform_test.zig's policies " ++
    "instantiate it";
const listener_kind = "starting a listener kind no seed binds beside the rest; server_test.zig " ++
    "starts every kind";
const dns_shape_part = dns_shape ++ partly_rare;
const extension_part = extension ++ partly_rare;
const h2_peer_part = h2_peer ++ partly_rare;
const h2_tls_part = h2_tls ++ partly_rare;
const head_shape_part = head_shape ++ partly_rare;
const log_sink_part = log_sink ++ partly_rare;
const origin_answer_part = origin_answer ++ partly_rare;
const tls_shape_part = tls_shape ++ partly_rare;
const unix_part = unix ++ partly_rare;

pub const exemptions = [_]Exemption{
    .{ .path = "Server.zig", .owner = "armLoopWatchdog", .lines = 11, .reason = watchdog_off },
    .{ .path = "Server.zig", .owner = "onLoopWatchdogTick", .lines = 4, .reason = watchdog_off },
    .{ .path = "Server.zig", .owner = "accountConnectionLine", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "acquireSharedStream", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "acquireTlsAdmission", .lines = 3, .reason = h2_tls },
    .{ .path = "Server.zig", .owner = "admittedBy", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "admittedByPolicies", .lines = 2, .reason = extension },
    .{ .path = "Server.zig", .owner = "admittedByRoutePolicies", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "appData", .lines = 1, .reason = tls_shape },
    .{ .path = "Server.zig", .owner = "beginDrain", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "bindExtensions", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "bindProbe", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "bindRoutePolicies", .lines = 2, .reason = extension },
    .{ .path = "Server.zig", .owner = "bindSniRoutePolicies", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "callPicker", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "callResponsePolicy", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "completeConnectionPolicies", .lines = 7, .reason = extension },
    .{ .path = "Server.zig", .owner = "completePick", .lines = 2, .reason = extension_part },
    .{ .path = "Server.zig", .owner = "completePickAtRelease", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "completePolicies", .lines = 3, .reason = extension },
    .{ .path = "Server.zig", .owner = "completePoliciesAtLine", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "declaredConsult", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "driveTlsHandshake", .lines = 1, .reason = tls_shape },
    .{ .path = "Server.zig", .owner = "evaluatePolicies", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "evaluateResponsePolicies", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "finishProxyHeader", .lines = 1, .reason = proxy_header },
    .{ .path = "Server.zig", .owner = "finishTlsHandshake", .lines = 4, .reason = h2_tls },
    .{ .path = "Server.zig", .owner = "lookupEndpointSet", .lines = 8, .reason = extension },
    .{ .path = "Server.zig", .owner = "noteConnectionProceeded", .lines = 4, .reason = extension },
    .{ .path = "Server.zig", .owner = "notePick", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "notePickConnected", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "notePickHead", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "notePoliciesProceeded", .lines = 2, .reason = extension },
    .{ .path = "Server.zig", .owner = "noteRouted", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "onConnect", .lines = 2, .reason = rare },
    .{ .path = "Server.zig", .owner = "onDeadline", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "onSignal", .lines = 3, .reason = signal },
    .{ .path = "Server.zig", .owner = "onTlsSent", .lines = 1, .reason = tls_shape },
    .{ .path = "Server.zig", .owner = "onTunnelDrainDeadline", .lines = 13, .reason = tunnel_drain },
    .{ .path = "Server.zig", .owner = "probeBufferBytes", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "releasePooledResources", .lines = 3, .reason = schedule_part },
    .{ .path = "Server.zig", .owner = "releaseSharedStream", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "resetLogHeaders", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "returnHeadBuffer", .lines = 1, .reason = rare },
    .{ .path = "Server.zig", .owner = "runResponsePolicies", .lines = 3, .reason = extension_part },
    .{ .path = "Server.zig", .owner = "selectsConsultingPolicy", .lines = 1, .reason = extension },
    .{ .path = "Server.zig", .owner = "selectsExtensions", .lines = 3, .reason = extension },
    .{ .path = "Server.zig", .owner = "selectsOnRoute", .lines = 2, .reason = extension },
    .{ .path = "Server.zig", .owner = "start", .lines = 1, .reason = listener_kind },
    .{ .path = "Server.zig", .owner = "takeEdits", .lines = 2, .reason = extension },
    .{ .path = "access_log.zig", .owner = "captureTruncated", .lines = 5, .reason = head_shape },
    .{ .path = "access_log.zig", .owner = "onWritten", .lines = 8, .reason = log_sink_part },
    .{ .path = "access_log.zig", .owner = "performReopen", .lines = 12, .reason = log_sink },
    .{ .path = "access_log.zig", .owner = "record", .lines = 3, .reason = census },
    .{ .path = "access_log.zig", .owner = "renderInto", .lines = 2, .reason = unix_part },
    .{ .path = "access_log.zig", .owner = "requestReopen", .lines = 7, .reason = log_sink },
    .{ .path = "access_log.zig", .owner = "writeNamedHeaders", .lines = 1, .reason = rare },
    .{ .path = "admin.zig", .owner = "onDeadline", .lines = 5, .reason = schedule_part },
    .{ .path = "admin.zig", .owner = "onSend", .lines = 1, .reason = schedule_part },
    .{ .path = "balancer.zig", .owner = "bytesKey", .lines = 2, .reason = balance_shape },
    .{ .path = "balancer.zig", .owner = "bytesKeyOf", .lines = 8, .reason = balance_shape },
    .{ .path = "balancer.zig", .owner = "countOf", .lines = 6, .reason = test_support },
    .{ .path = "balancer.zig", .owner = "endpointId", .lines = 2, .reason = unix },
    .{ .path = "balancer.zig", .owner = "ipEndpoint", .lines = 2, .reason = test_support },
    .{ .path = "balancer.zig", .owner = "parseEndpointTag", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "balancer.zig", .owner = "rampedCap", .lines = 7, .reason = rare },
    .{ .path = "config.zig", .owner = "bindLessThan", .lines = 2, .reason = unix },
    .{ .path = "config.zig", .owner = "bindOrder", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "bodyNamed", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "config.zig", .owner = "grpcServiceValid", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "hostBitsSet", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "config.zig", .owner = "kind", .lines = 2, .reason = startup },
    .{ .path = "config.zig", .owner = "lessThan", .lines = 8, .reason = config_shape },
    .{ .path = "config.zig", .owner = "reachableEndpoints", .lines = 9, .reason = startup },
    .{ .path = "config.zig", .owner = "rejectDuplicateQuicBinds", .lines = 8, .reason = config_shape },
    .{ .path = "config.zig", .owner = "rejectUnixClientAddressUsers", .lines = 12, .reason = unix },
    .{ .path = "config.zig", .owner = "rejectUnixCluster", .lines = 5, .reason = unix },
    .{ .path = "config.zig", .owner = "resolve", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveAccessLogBuffer", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveAccessLogSink", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveAction", .lines = 2, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveBindAddress", .lines = 4, .reason = unix },
    .{ .path = "config.zig", .owner = "resolveBindMode", .lines = 5, .reason = unix },
    .{ .path = "config.zig", .owner = "resolveEndpointAddress", .lines = 4, .reason = unix },
    .{ .path = "config.zig", .owner = "resolveErrorPages", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveHeaderMatches", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveHttpCheck", .lines = 4, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveLimits", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveListener", .lines = 1, .reason = unix },
    .{ .path = "config.zig", .owner = "resolveListenerResponseFilters", .lines = 1, .reason = unix },
    .{ .path = "config.zig", .owner = "resolveLogHeaderNames", .lines = 2, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveRedirect", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveRequestFilters", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveResponseEdit", .lines = 4, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveResponseFilters", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveRoutes", .lines = 4, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveTlsEngines", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "resolveUnixPath", .lines = 5, .reason = unix },
    .{ .path = "config.zig", .owner = "resolveUpstreamTls", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "routeHeaderEql", .lines = 6, .reason = config_shape },
    .{ .path = "config.zig", .owner = "routeOrderMoreSpecific", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "socketsFor", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "validateDnsName", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "validateRouteName", .lines = 1, .reason = config_shape },
    .{ .path = "config.zig", .owner = "validateTimeouts", .lines = 4, .reason = watchdog },
    .{ .path = "constants.zig", .owner = "assertH2Terms", .lines = 10, .reason = comptime_only },
    .{ .path = "constants.zig", .owner = "assertH3Terms", .lines = 7, .reason = comptime_only },
    .{ .path = "constants.zig", .owner = "bufferGroupDescriptorBytes", .lines = 7, .reason = startup },
    .{ .path = "constants.zig", .owner = "completionQueueDepthFor", .lines = 11, .reason = startup },
    .{ .path = "constants.zig", .owner = "resolverOps", .lines = 2, .reason = startup },
    .{ .path = "counters.zig", .owner = "kernelPressureCauseTotal", .lines = 1, .reason = startup },
    .{ .path = "counters.zig", .owner = "labeledTestAddress", .lines = 2, .reason = test_support },
    .{ .path = "counters.zig", .owner = "render", .lines = 2, .reason = kcov_line },
    .{ .path = "counters.zig", .owner = "set", .lines = 2, .reason = test_support },
    .{ .path = "counters.zig", .owner = "tableBytes", .lines = 27, .reason = startup },
    .{ .path = "counters.zig", .owner = "writeEscaped", .lines = 2, .reason = head_shape },
    .{ .path = "dns/endpoints.zig", .owner = "mergeDuplicates", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/host.zig", .owner = "canonical", .lines = 9, .reason = startup },
    .{ .path = "dns/host.zig", .owner = "isCanonical", .lines = 2, .reason = dns_shape },
    .{ .path = "dns/message.zig", .owner = "addressBytes", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/message.zig", .owner = "addressFits", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/message.zig", .owner = "collectAddresses", .lines = 2, .reason = dns_shape },
    .{ .path = "dns/message.zig", .owner = "followCnames", .lines = 7, .reason = dns_shape },
    .{ .path = "dns/message.zig", .owner = "readName", .lines = 6, .reason = dns_shape_part },
    .{ .path = "dns/message.zig", .owner = "readRecord", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/message.zig", .owner = "writeReply", .lines = 4, .reason = dns_shape },
    .{ .path = "dns/resolver.zig", .owner = "accept", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/resolver.zig", .owner = "bytesFor", .lines = 7, .reason = startup },
    .{ .path = "dns/resolver.zig", .owner = "freshId", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/resolver.zig", .owner = "initRounds", .lines = 1, .reason = dns_shape },
    .{ .path = "dns/resolver.zig", .owner = "offerSet", .lines = 1, .reason = dns_shape },
    .{ .path = "extension.zig", .owner = "bytes", .lines = 1, .reason = extension },
    .{ .path = "extension.zig", .owner = "capacity", .lines = 5, .reason = extension },
    .{ .path = "extension.zig", .owner = "clusterNamed", .lines = 1, .reason = extension },
    .{ .path = "extension.zig", .owner = "counter", .lines = 3, .reason = extension },
    .{ .path = "extension.zig", .owner = "gauge", .lines = 3, .reason = extension },
    .{ .path = "extension.zig", .owner = "routeNamed", .lines = 1, .reason = extension },
    .{ .path = "extension.zig", .owner = "select", .lines = 1, .reason = extension },
    .{ .path = "extension.zig", .owner = "take", .lines = 2, .reason = extension },
    .{ .path = "extension_answers.zig", .owner = "init", .lines = 2, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "blockBytes", .lines = 6, .reason = startup },
    .{ .path = "extension_metrics.zig", .owner = "buildList", .lines = 1, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "firstOf", .lines = 1, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "init", .lines = 2, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "listenerPolicies", .lines = 1, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "picker", .lines = 1, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "render", .lines = 1, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "renderBytesMaxFor", .lines = 1, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "tableBytes", .lines = 17, .reason = startup },
    .{ .path = "extension_metrics.zig", .owner = "visit", .lines = 5, .reason = startup },
    .{ .path = "extension_metrics.zig", .owner = "writeLabel", .lines = 4, .reason = extension },
    .{ .path = "extension_metrics.zig", .owner = "writeRoute", .lines = 2, .reason = extension },
    .{ .path = "http/consult.zig", .owner = "begin", .lines = 2, .reason = extension },
    .{ .path = "http/consult.zig", .owner = "slotsFor", .lines = 1, .reason = extension },
    .{ .path = "http/filter.zig", .owner = "appliedEdit", .lines = 1, .reason = config_shape },
    .{ .path = "http/filter.zig", .owner = "isRedirectStatus", .lines = 2, .reason = config_shape },
    .{ .path = "http/filter.zig", .owner = "isRejectStatus", .lines = 1, .reason = config_shape },
    .{ .path = "http/filter.zig", .owner = "prefixBitsMatch", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "http/filter.zig", .owner = "responseMatches", .lines = 1, .reason = config_shape },
    .{ .path = "http/filter.zig", .owner = "rewritePath", .lines = 14, .reason = config_shape },
    .{ .path = "http/grpc.zig", .owner = "fieldValue", .lines = 1, .reason = rare },
    .{ .path = "http/grpc.zig", .owner = "isGrpc", .lines = 2, .reason = grpc_timeout },
    .{ .path = "http/grpc.zig", .owner = "requestTimeoutNs", .lines = 1, .reason = rare },
    .{ .path = "http/grpc.zig", .owner = "timeoutNs", .lines = 4, .reason = grpc_timeout },
    .{ .path = "http/h2/Connection.zig", .owner = "expire", .lines = 5, .reason = rare },
    .{ .path = "http/h2/Connection.zig", .owner = "flush", .lines = 1, .reason = h2_tls },
    .{ .path = "http/h2/Connection.zig", .owner = "goingAway", .lines = 4, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "canSend", .lines = 1, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "creditConnection", .lines = 4, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "creditStream", .lines = 4, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "decodeBlock", .lines = 2, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "encodeResize", .lines = 1, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "flushPending", .lines = 4, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "framesFor", .lines = 1, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "handleData", .lines = 6, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "handleFrame", .lines = 3, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "handleResponseBlock", .lines = 2, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "handleSettings", .lines = 3, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "handleTrailers", .lines = 1, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "inputDrained", .lines = 2, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "openStream", .lines = 2, .reason = rare },
    .{ .path = "http/h2/Session.zig", .owner = "retunePeerWindows", .lines = 2, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "selfDependent", .lines = 1, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "sendFields", .lines = 1, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "spreadBlock", .lines = 6, .reason = h2_peer_part },
    .{ .path = "http/h2/Session.zig", .owner = "step", .lines = 2, .reason = h2_peer_part },
    .{ .path = "http/h2/Session.zig", .owner = "streamError", .lines = 15, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "takeFrame", .lines = 11, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "takePreface", .lines = 2, .reason = h2_peer },
    .{ .path = "http/h2/Session.zig", .owner = "takeResponseHead", .lines = 2, .reason = h2_peer_part },
    .{ .path = "http/h2/downgrade.zig", .owner = "byte", .lines = 4, .reason = test_support },
    .{ .path = "http/h2/downgrade.zig", .owner = "isOriginOrAsterisk", .lines = 1, .reason = h2_request },
    .{ .path = "http/h2/downgrade.zig", .owner = "mapInto", .lines = 4, .reason = test_support },
    .{ .path = "http/h2/downgrade.zig", .owner = "readPseudo", .lines = 1, .reason = h2_request },
    .{ .path = "http/h2/downgrade.zig", .owner = "requestHead", .lines = 1, .reason = h2_request },
    .{ .path = "http/h2/downgrade.zig", .owner = "string", .lines = 4, .reason = test_support },
    .{ .path = "http/h2/downgrade.zig", .owner = "validated", .lines = 5, .reason = test_support },
    .{ .path = "http/h2/exchange.zig", .owner = "bytesFor", .lines = 1, .reason = h2_request },
    .{ .path = "http/h2/exchange.zig", .owner = "drop", .lines = 5, .reason = rare },
    .{ .path = "http/h2/exchange.zig", .owner = "init", .lines = 1, .reason = h2_request },
    .{ .path = "http/h2/exchange.zig", .owner = "requestWindow", .lines = 1, .reason = h2_request },
    .{ .path = "http/h2/origin.zig", .owner = "noBody", .lines = 6, .reason = origin_answer },
    .{ .path = "http/h2/origin.zig", .owner = "nominated", .lines = 7, .reason = origin_answer },
    .{ .path = "http/h2/origin.zig", .owner = "path", .lines = 10, .reason = origin_answer },
    .{ .path = "http/h2/origin.zig", .owner = "request", .lines = 2, .reason = test_support },
    .{ .path = "http/h2/origin.zig", .owner = "requestCarries", .lines = 2, .reason = origin_answer },
    .{ .path = "http/h2/origin_pool.zig", .owner = "compose", .lines = 2, .reason = grpc_service },
    .{ .path = "http/h2/origin_pool.zig", .owner = "drive", .lines = 2, .reason = rare },
    .{ .path = "http/h2/origin_pool.zig", .owner = "nextOf", .lines = 1, .reason = rare },
    .{ .path = "http/h2/origin_pool.zig", .owner = "onConnect", .lines = 1, .reason = rare },
    .{ .path = "http/h2/origin_pool.zig", .owner = "stepEvents", .lines = 2, .reason = rare },
    .{ .path = "http/h2/origin_pool.zig", .owner = "streamWindow", .lines = 1, .reason = kcov_line },
    .{ .path = "http/h2/origin_pool.zig", .owner = "tlsFailed", .lines = 5, .reason = h2_origin_tls },
    .{ .path = "http/h2/response.zig", .owner = "carried", .lines = 2, .reason = origin_answer },
    .{ .path = "http/h2/response.zig", .owner = "nominated", .lines = 7, .reason = origin_answer },
    .{ .path = "http/h3/driver.zig", .owner = "refreshDeadline", .lines = 1, .reason = rare },
    .{ .path = "http/h3/exchange.zig", .owner = "capRequests", .lines = 6, .reason = h3_peer },
    .{ .path = "http/parser.zig", .owner = "appendNameByte", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "authorityIsWellFormed", .lines = 2, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "canonicalHost", .lines = 3, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "canonicalTarget", .lines = 2, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "classifyHeaderName", .lines = 1, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "collapseDotSegments", .lines = 6, .reason = head_shape_part },
    .{ .path = "http/parser.zig", .owner = "cookieValue", .lines = 2, .reason = head_shape_part },
    .{ .path = "http/parser.zig", .owner = "decodeTargetPath", .lines = 7, .reason = head_shape_part },
    .{ .path = "http/parser.zig", .owner = "foldHeader", .lines = 4, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "fullHeadVerdict", .lines = 1, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "hexNibble", .lines = 1, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "hopByHop", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "keepAliveDefault", .lines = 1, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "maxForwards", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "oversizeRequestError", .lines = 1, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "parseDecimal", .lines = 4, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "parseRequestHead", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "http/parser.zig", .owner = "parseRequestRaw", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "parseResponseHead", .lines = 4, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "protected", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "refusedHeadError", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "requestFraming", .lines = 3, .reason = kcov_line_x86 },
    .{ .path = "http/parser.zig", .owner = "responseFraming", .lines = 5, .reason = kcov_line_x86 },
    .{ .path = "http/parser.zig", .owner = "splitAbsoluteForm", .lines = 3, .reason = kcov_line_x86 },
    .{ .path = "http/parser.zig", .owner = "stepDataEnd", .lines = 2, .reason = kcov_line_x86 },
    .{ .path = "http/parser.zig", .owner = "stepSizeLine", .lines = 9, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "stepTrailer", .lines = 3, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "tokenListHas", .lines = 1, .reason = rare },
    .{ .path = "http/parser.zig", .owner = "upperHexDigit", .lines = 5, .reason = head_shape },
    .{ .path = "http/parser.zig", .owner = "versionFromRaw", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "admitRequest", .lines = 2, .reason = head_shape },
    .{ .path = "http/proxy.zig", .owner = "admitUpgrade", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "answerHeadOverflow", .lines = 1, .reason = census },
    .{ .path = "http/proxy.zig", .owner = "appendInboundChain", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "armRequestDeadline", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "beginHandler", .lines = 1, .reason = head_shape },
    .{ .path = "http/proxy.zig", .owner = "callHandler", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "clientAddressOf", .lines = 1, .reason = unix },
    .{ .path = "http/proxy.zig", .owner = "coalesceResponseExcess", .lines = 1, .reason = origin_answer },
    .{ .path = "http/proxy.zig", .owner = "composeLocation", .lines = 2, .reason = config_shape },
    .{ .path = "http/proxy.zig", .owner = "dispatchByStatus", .lines = 2, .reason = origin_answer_part },
    .{ .path = "http/proxy.zig", .owner = "dispatchHead", .lines = 3, .reason = head_shape },
    .{ .path = "http/proxy.zig", .owner = "expireExchange", .lines = 3, .reason = schedule_part },
    .{ .path = "http/proxy.zig", .owner = "expiryAnswerable", .lines = 2, .reason = kcov_line_x86 },
    .{ .path = "http/proxy.zig", .owner = "listenerPhase", .lines = 1, .reason = census },
    .{ .path = "http/proxy.zig", .owner = "onClientWritten", .lines = 2, .reason = origin_answer },
    .{ .path = "http/proxy.zig", .owner = "onHeadRecv", .lines = 2, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "onRequestExcessSent", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "onRequestHeadSent", .lines = 4, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "onSendEntry", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "onTlsHeadRecv", .lines = 2, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "onUpstreamConnect", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "parseAndDispatch", .lines = 1, .reason = census },
    .{ .path = "http/proxy.zig", .owner = "parseResponseUnderBorrow", .lines = 1, .reason = origin_answer },
    .{ .path = "http/proxy.zig", .owner = "planClientNames", .lines = 3, .reason = tls_shape },
    .{ .path = "http/proxy.zig", .owner = "planForward", .lines = 2, .reason = extension_part },
    .{ .path = "http/proxy.zig", .owner = "planForwarded", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "planMaxForwards", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "http/proxy.zig", .owner = "readMoreHead", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "refuseH2Request", .lines = 6, .reason = h2_request },
    .{ .path = "http/proxy.zig", .owner = "refusedByPolicies", .lines = 1, .reason = extension },
    .{ .path = "http/proxy.zig", .owner = "replayEligible", .lines = 2, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "respondPolicy", .lines = 2, .reason = extension },
    .{ .path = "http/proxy.zig", .owner = "respondRedirect", .lines = 1, .reason = head_shape },
    .{ .path = "http/proxy.zig", .owner = "routeOf", .lines = 1, .reason = rare },
    .{ .path = "http/proxy.zig", .owner = "sendResponseExcess", .lines = 6, .reason = origin_answer },
    .{ .path = "http/proxy.zig", .owner = "start", .lines = 2, .reason = census },
    .{ .path = "http/proxy.zig", .owner = "targetViews", .lines = 2, .reason = head_shape },
    .{ .path = "http/render.zig", .owner = "append", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "http/render.zig", .owner = "appendEndToEndHeaders", .lines = 1, .reason = head_shape },
    .{ .path = "http/render.zig", .owner = "claims", .lines = 1, .reason = tls_shape },
    .{ .path = "http/render.zig", .owner = "renderRequestHead", .lines = 1, .reason = head_shape },
    .{ .path = "http/router.zig", .owner = "headerMatches", .lines = 1, .reason = config_shape },
    .{ .path = "http/router.zig", .owner = "match", .lines = 3, .reason = test_support },
    .{ .path = "http/router.zig", .owner = "matchIndex", .lines = 1, .reason = config_shape },
    .{ .path = "http/router.zig", .owner = "prefixMatches", .lines = 1, .reason = config_shape },
    .{ .path = "http/router.zig", .owner = "route", .lines = 3, .reason = test_support },
    .{ .path = "io/io.zig", .owner = "eql", .lines = 2, .reason = unix },
    .{ .path = "io/io.zig", .owner = "format", .lines = 2, .reason = unix },
    .{ .path = "io/io.zig", .owner = "pathIsRenderable", .lines = 6, .reason = unix },
    .{ .path = "net/client_hello.zig", .owner = "byte", .lines = 3, .reason = test_support },
    .{ .path = "net/client_hello.zig", .owner = "hello", .lines = 22, .reason = test_support },
    .{ .path = "net/client_hello.zig", .owner = "int16", .lines = 3, .reason = test_support },
    .{ .path = "net/client_hello.zig", .owner = "parse", .lines = 1, .reason = rare },
    .{ .path = "net/client_hello.zig", .owner = "parseExtensions", .lines = 1, .reason = hello_shape },
    .{ .path = "net/client_hello.zig", .owner = "parseHandshake", .lines = 3, .reason = kcov_line_x86 },
    .{ .path = "net/client_hello.zig", .owner = "parseHello", .lines = 2, .reason = rare },
    .{ .path = "net/client_hello.zig", .owner = "parseServerName", .lines = 2, .reason = hello_shape },
    .{ .path = "net/client_hello.zig", .owner = "slice", .lines = 3, .reason = test_support },
    .{ .path = "net/client_hello.zig", .owner = "takeVector", .lines = 2, .reason = hello_shape },
    .{ .path = "net/health.zig", .owner = "beginCall", .lines = 1, .reason = kcov_line },
    .{ .path = "net/health.zig", .owner = "beginRequest", .lines = 4, .reason = health_shape },
    .{ .path = "net/health.zig", .owner = "beginRound", .lines = 3, .reason = census },
    .{ .path = "net/health.zig", .owner = "callProbeJudge", .lines = 2, .reason = extension },
    .{ .path = "net/health.zig", .owner = "onProbeDeadline", .lines = 1, .reason = schedule_part },
    .{ .path = "net/health.zig", .owner = "onProbeRecv", .lines = 1, .reason = health_shape },
    .{ .path = "net/health.zig", .owner = "onProbeSend", .lines = 1, .reason = health_shape },
    .{ .path = "net/health.zig", .owner = "settle", .lines = 1, .reason = census },
    .{ .path = "net/proxy_protocol.zig", .owner = "parseAny", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "net/proxy_protocol.zig", .owner = "parsePort", .lines = 3, .reason = kcov_line_x86 },
    .{ .path = "net/proxy_protocol.zig", .owner = "parseV1", .lines = 4, .reason = proxy_header },
    .{ .path = "net/proxy_protocol.zig", .owner = "parseV1Address", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "net/proxy_protocol.zig", .owner = "parseV1Proxy", .lines = 2, .reason = proxy_header },
    .{ .path = "net/proxy_protocol.zig", .owner = "parseV2", .lines = 6, .reason = kcov_line_x86 },
    .{ .path = "net/proxy_protocol.zig", .owner = "v2Address", .lines = 2, .reason = proxy_header },
    .{ .path = "net/proxy_protocol.zig", .owner = "v2AddressBytes", .lines = 1, .reason = proxy_header },
    .{ .path = "net/pump.zig", .owner = "onRecv", .lines = 4, .reason = schedule_part },
    .{ .path = "net/pump.zig", .owner = "sendSlice", .lines = 3, .reason = pump_policy },
    .{ .path = "net/sni_router.zig", .owner = "route", .lines = 3, .reason = test_support },
    .{ .path = "net/upstream.zig", .owner = "park", .lines = 1, .reason = rare },
    .{ .path = "net/upstream_tls.zig", .owner = "failTls", .lines = 3, .reason = rare },
    .{ .path = "pickers.zig", .owner = "bind", .lines = 6, .reason = extension },
    .{ .path = "pickers.zig", .owner = "loopback", .lines = 2, .reason = test_support },
    .{ .path = "pickers.zig", .owner = "materialOf", .lines = 2, .reason = extension },
    .{ .path = "policy_edits.zig", .owner = "copyEdit", .lines = 1, .reason = extension },
    .{ .path = "policy_edits.zig", .owner = "responseShapeOf", .lines = 1, .reason = extension },
    .{ .path = "policy_edits.zig", .owner = "shapeOf", .lines = 1, .reason = extension },
    .{ .path = "policy_edits.zig", .owner = "take", .lines = 1, .reason = extension },
    .{ .path = "policy_edits.zig", .owner = "takeResponse", .lines = 1, .reason = extension },
    .{ .path = "shed.zig", .owner = "formatHttpDate", .lines = 1, .reason = rare },
    .{ .path = "shed.zig", .owner = "get", .lines = 5, .reason = census },
    .{ .path = "shed.zig", .owner = "getGrpcDeadline", .lines = 1, .reason = rare },
    .{ .path = "shed.zig", .owner = "isStaticStatus", .lines = 1, .reason = config_shape },
    .{ .path = "shed.zig", .owner = "pageStatusIndex", .lines = 1, .reason = config_shape },
    .{ .path = "shed.zig", .owner = "proxyStatusCauseFor", .lines = 8, .reason = comptime_only },
    .{ .path = "tls/Credentials.zig", .owner = "expectKeyOfLeaf", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "tls/Credentials.zig", .owner = "load", .lines = 2, .reason = tls_shape },
    .{ .path = "tls/Credentials.zig", .owner = "rsaPairing", .lines = 2, .reason = tls_shape },
    .{ .path = "tls/Engine.zig", .owner = "feed", .lines = 10, .reason = tls_shape },
    .{ .path = "tls/Engine.zig", .owner = "openOfferedTicket", .lines = 1, .reason = rare },
    .{ .path = "tls/OriginClient.zig", .owner = "compactPlaintext", .lines = 4, .reason = tls_shape },
    .{ .path = "tls/OriginClient.zig", .owner = "deinit", .lines = 3, .reason = test_support },
    .{ .path = "tls/OriginClient.zig", .owner = "deliver", .lines = 9, .reason = test_support },
    .{ .path = "tls/OriginClient.zig", .owner = "feed", .lines = 11, .reason = test_support },
    .{ .path = "tls/OriginClient.zig", .owner = "init", .lines = 2, .reason = test_support },
    .{ .path = "tls/OriginClient.zig", .owner = "initServing", .lines = 10, .reason = test_support },
    .{ .path = "tls/QuicCrypto.zig", .owner = "deinit", .lines = 4, .reason = test_teardown },
    .{ .path = "tls/Tickets.zig", .owner = "open", .lines = 2, .reason = tls_shape_part },
    .{ .path = "tls/Tickets.zig", .owner = "slotFor", .lines = 1, .reason = tls_shape },
    .{ .path = "tls/alpn.zig", .owner = "fromToken", .lines = 2, .reason = config_shape },
    .{ .path = "tls/certificate_set.zig", .owner = "select", .lines = 1, .reason = rare },
    .{ .path = "tls/certificate_set.zig", .owner = "wildcardCovers", .lines = 1, .reason = rare },
    .{ .path = "tls/trust.zig", .owner = "anchored", .lines = 1, .reason = kcov_line_x86 },
    .{ .path = "tls/trust.zig", .owner = "clientNames", .lines = 19, .reason = tls_shape },
    .{ .path = "tls/trust.zig", .owner = "keep", .lines = 13, .reason = tls_shape },
    .{ .path = "tls/trust.zig", .owner = "pathVerifies", .lines = 4, .reason = tls_shape },
    .{ .path = "tls/trust.zig", .owner = "read", .lines = 1, .reason = rare },
    .{ .path = "tls/trust.zig", .owner = "value", .lines = 5, .reason = tls_shape },
};
