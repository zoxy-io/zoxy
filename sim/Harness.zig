//! One scenario of the simulation gate (§9): every seed derives a
//! topology (client count, seed-derived tokens, adversary knobs, pool
//! sizes that force the §8 rungs, misbehaving-origin scripts) and runs
//! the *real* serving path over SimIo. Scenarios mix protocols: an L4
//! echo population (sim/l4.zig) and an L7 HTTP population (sim/l7.zig)
//! share one server, so the pools feel cross-protocol pressure. A
//! quarter of seeds run *clean* — the adversary off and the origin
//! well-behaved — hardening the oracles from prefix-legality to the
//! scripts' exact golden outcomes.
//!
//! Invariants per seed: no deadlock, pools drain to zero, counters
//! reconcile, every L4 echo byte is a prefix of what was sent, every L7
//! response is a prefix of a legal transcript, no malformed byte ever
//! reaches the origin (§7), and every virtual socket is released.

const std = @import("std");

const zoxy = @import("zoxy");

const admin = @import("admin.zig");
const l4 = @import("l4.zig");
const l7 = @import("l7.zig");

const Io = zoxy.Io;
const SimIo = zoxy.Io.SimIo;
/// The sweep's runtime lists one picker (#417), which some seeds select
/// for a cluster, so the extension dispatch and its fallback run under the
/// adversary like every other part of the pick.
const runtime: zoxy.Runtime = .{
    .Io = SimIo,
    .extensions = .{
        .pickers = &.{zoxy.testing.ScriptedPicker},
        .request_policies = &.{ zoxy.testing.ScriptedPolicy, zoxy.testing.ScriptedConsultOpenPolicy },
        .response_policies = &.{zoxy.testing.ScriptedResponsePolicy},
        .connection_policies = &.{zoxy.testing.ScriptedConnectionPolicy},
        .probes = &.{zoxy.testing.ScriptedProbe},
        .handlers = &.{zoxy.testing.ScriptedHandler},
    },
};
const ServerSim = zoxy.Server(runtime);
const Origin = zoxy.testing.Origin(SimIo);
const HttpOrigin = l7.HttpOrigin(SimIo);
const HttpClient = l7.Client(SimIo);
const H2Client = l7.H2Client(SimIo);
const H3Client = l7.H3Client(SimIo);
const EchoClient = l4.Client(SimIo);
const AdminScraper = admin.Scraper(SimIo);
/// The HTTP/2 origin of a seed whose http cluster speaks it (#275): enough
/// connections for a pool the adversary keeps redialing.
const H2Origin = zoxy.http.h2.TestOriginSized(SimIo, 32);
/// The HTTPS origin of a seed whose http cluster speaks HTTP/1.1 over TLS
/// (#296), sized as the HTTP/2 one.
const HttpsOrigin = zoxy.testing.HttpsOrigin(SimIo, 32);
/// The scripted nameservers a DNS-following seed's resolver asks (#481).
const Nameserver = zoxy.testing.Nameserver(SimIo);
const TlsClient = zoxy.tls.TestClient(SimIo);

const assert = std.debug.assert;

const Harness = @This();

const clients_max: u8 = 6;
/// The §4 terminating population one seed may draw (#125). Small on
/// purpose: a real ECDSA handshake is ~260 µs of libcrypto on each side,
/// so a sweep that gave every client a session would cost minutes rather
/// than the seconds this gate is run at. Two is enough to reach the
/// engine-pool wall on a starved seed, which is the one rung that needs
/// more than one.
const tls_clients_max: u8 = 2;
/// One more slot than a seed may draw, for the resuming client (#204).
/// Exactly one: what it covers is a ticket surviving from one connection
/// to the next, and a second resumer would only re-cover it while
/// doubling the handshake crypto every TLS seed pays for.
const tls_client_slots: u8 = tls_clients_max + 1;
/// Every downstream connection one seed's population can hold at once:
/// the plaintext clients, the terminating ones, and the resumer. Not
/// `clients_max` — the clean-seed pools were sized off that alone, so a
/// seed drawing the full population of both (6 + 2 + 1) held exactly the
/// 9 of 12 that engages the §8 watermark, and seed 284647213's
/// `keepalive_pair` met a pressure-announced close on a clean seed.
const connections_max: u8 = clients_max + tls_client_slots + h3_clients_max;
/// The HTTP/3 population's largest (#449): each a QUIC connection to the
/// terminating listener's binding, with up to `H3Client.streams_max`
/// requests.
const h3_clients_max: u8 = 2;
/// Every exchange one seed's population can hold at once: `connections_max`
/// with each plaintext client counted as an HTTP/2 one at its most streams
/// (#275), since each stream holds a relay buffer, an upstream slot and an
/// upstream head buffer of its own. Counting connections alone let three
/// nightly seeds (448156674, 449268806, 450273021) engage relay pressure
/// on a clean seed, so their `keepalive_pair` met a pressure-announced
/// close beside four HTTP/2 clients.
/// A TLS slot that speaks HTTP/2 (`tls_h2`) opens its exchange's streams
/// as an h2c client does, so each slot counts as that many.
const exchanges_max: u32 = @as(u32, clients_max) * H2Client.streams_max +
    @as(u32, tls_client_slots) * H2Client.streams_max +
    @as(u32, h3_clients_max) * H3Client.streams_max;
/// Every pool's capacity on a clean seed, sized so its §8 pressure
/// watermark sits above `exchanges_max`: a golden outcome must never meet
/// a pressure-announced close or a shortened deadline — correct behavior,
/// but not the script's exact transcript.
const clean_pool_capacity: u32 = 2 * exchanges_max;
/// An adversarial seed's consult slots (#437): fewer than one HTTP/2
/// client's streams, so a connection that consults on every one of them
/// holds the pool and the next meets its wall (`slots_exhausted`).
const adversarial_consult_slots: u32 = 2;
/// Bytes each terminating client echoes. Small: what this population is
/// for is the handshake and the transform, not throughput.
const tls_token_bytes: u8 = 24;
/// The two requests a terminating *http* listener's client sends, in
/// order. Both are the L7 scripts' own bytes, so the origin answers them
/// exactly as it answers a plaintext client's and the difference under
/// test is the transform rather than the request.
///
/// The first is a keep-alive POST: a body, which a GET has none of, and
/// no `Connection: close`, so the exchange leaves the connection open.
/// The second closes it, which is how the client ends without waiting on
/// an idle timeout. Between them is the keep-alive turnaround — the L7
/// state re-entered on a terminated connection, which is where the head
/// source's first defect lived (#204).
const tls_http_followup = l7.scripts.get_request_close;

/// What one terminating client offers in ALPN (#271). The server's side
/// is fixed by the listener — HTTP/1.1 on an `http` terminator, nothing on
/// an `l4` one — so the draw is on the client's, which is where every
/// verdict RFC 7301 §3.2 can reach comes from: a match, no offer at all,
/// a match that is not the client's first choice, and an offer the
/// listener cannot meet.
const TlsAlpnOffer = enum {
    none,
    http_1_1,
    h2_then_http_1_1,
    h2_only,

    fn protocols(offer: TlsAlpnOffer) []const []const u8 {
        return switch (offer) {
            .none => &.{},
            .http_1_1 => &.{"http/1.1"},
            .h2_then_http_1_1 => &.{ "h2", "http/1.1" },
            .h2_only => &.{"h2"},
        };
    }
};
/// "203.0.113.255:65535" is 19 bytes; the slack is headroom, not hope.
const announced_bytes_max: u8 = 32;
/// The /24 an announcing L4 client's header names it from, and the one
/// the connection policy refuses (#425): TEST-NET-3 and TEST-NET-1 —
/// not TEST-NET-2, which SimIo's own peers are observed from.
const announced_network = [3]u8{ 203, 0, 113 };
const denied_network = [3]u8{ 192, 0, 2 };
/// Virtual time from scenario start after which stuck work is force-ended.
const scenario_end_ns: u64 = 2_000_000_000;
/// Scrapers one seed sends the admin listener at most.
const admin_scrapers_max: u8 = 2;
/// How far a #202 seed steps the wall clock: one whole rotation interval
/// plus a second, so the key is unambiguously overdue rather than
/// balanced on the boundary the directed tests already pin.
const clock_jump_ns: u64 =
    (@as(u64, zoxy.constants.tls_ticket_key_rotation_s) + 1) * std.time.ns_per_s;
/// The slowest §7 probe pacing a non-outage seed may draw. Named so the
/// origin-capacity bound below is derived from the same number the draw
/// uses, not restated in prose.
const health_interval_floor_ms: u32 = 100;
/// Upper bound on probe sweeps one scenario can run against a listening
/// origin: the interval floor paces them across the scenario, plus the
/// immediate first sweep. Outage seeds pace far tighter but stop their
/// origin within tens of milliseconds, so their passing probes stay
/// under this bound too.
const probe_sweeps_max: u64 =
    scenario_end_ns / (health_interval_floor_ms * std.time.ns_per_ms) + 1;

/// Where a stranding seed places its drop (#206). Two hooks, because the
/// two halves of the class need different instants: `wind_down` takes ops
/// already armed when the drain begins, `teardown` waits for the first
/// cancel submitted once it is under way. Neither is a superset of the
/// other — see `maybeStrandOps` and `armTeardownStrand`.
const DropMode = enum { wind_down, teardown };

/// What the teardown latch waits for. `beginTeardown` arms exactly these
/// two — a pending dial's `connect_cancel` and a live deadline's
/// `timer_cancel` — and it arms them *after* a wind-down drop has already
/// landed, which is what puts them out of that hook's reach.
const teardown_strand_kinds = [_]SimIo.OpKind{ .timer_cancel, .connect_cancel };

comptime {
    // Passing probes consume origin conn slots (accept-and-vanish), on
    // top of each origin's client-driven worst case: one conn per L4
    // client, and the pre-probe capacity of 32 the 4096-seed sweeps
    // validated for the HTTP origin's HTTP/1.1 dial churn. The HTTP
    // origin reuses a closed slot only once these are spent, which a
    // Rapid Reset flood's dial per round does (#276).
    assert(Origin.conns_max >= @as(u64, clients_max) + probe_sweeps_max);
    assert(HttpOrigin.conns_max >= 32 + probe_sweeps_max);
    // `deriveRelayBufferBytes` draws up to the default, which a
    // terminating listener allows (`LimitRelayBufferOverTlsRecord`).
    assert(zoxy.constants.relay_buffer_bytes_default <= zoxy.constants.tls_app_chunk_bytes);
    // An HTTP/2 client's largest body (#373) reaches the origin whole in
    // its request buffer: beside the forwarded head, and the chunk framing
    // the proxy adds when the length was not declared, a size line and
    // CRLF per forwarded chunk, under ten octets. The allowance covers
    // some two hundred chunks. A small relay buffer cuts a held frame into
    // about a dozen, and deliveries cut it further, which no bound here
    // proves. A body past the allowance would read as forwarded excess,
    // `OriginSawMalformedBytes`, which would name this comment.
    const forwarded_head_bytes_max: u32 = 1024;
    const chunk_framing_bytes_max: u32 = 2048;
    assert(l7.h2_body_bytes_max + forwarded_head_bytes_max + chunk_framing_bytes_max <=
        HttpOrigin.request_buffer_bytes);
    // The clean-seed margin, as a proof rather than a comment: every
    // exchange the population can hold at once still stops short of the
    // watermark, and an exchange per connection is the least of it.
    assert(exchanges_max >= connections_max);
    assert(zoxy.constants.poolPressureOn(clean_pool_capacity) > exchanges_max);
    // And within what a deployment may configure, so a population bump
    // fails here rather than at `Server.init`.
    assert(clean_pool_capacity <= zoxy.constants.conn_slots_max);
    assert(clean_pool_capacity <= zoxy.constants.relay_buffers_max);
    assert(clean_pool_capacity <= zoxy.constants.upstream_slots_max);
    // A clean seed's consult slots (#437), one per exchange, within the
    // upstream slots each consult holds one of — and an adversarial
    // seed's, fewer than one HTTP/2 client's streams.
    assert(exchanges_max <= clean_pool_capacity);
    assert(adversarial_consult_slots < H2Client.streams_max);
}

io: SimIo,
server: ServerSim,
endpoints_l4: [1]zoxy.Io.Address,
/// The http cluster's endpoints: the origin at index 0 always, and on a
/// #181 retry seed a second one nothing is listening on (`deriveRetries`).
/// How many are configured is `endpoints_http_count`.
endpoints_http: [2]zoxy.Io.Address,
endpoints_http_count: u16,
/// The #174 weight tables the clusters may reference, each as long as
/// the endpoint list it parallels.
weights_l4: [1]u16,
weights_http: [2]u16,
/// #396's tiers for a two-endpoint http cluster: the origin in standby
/// behind the refusing endpoint, so every request that reaches the origin
/// does so by failing over to it — a retry off the refused primary, or the
/// healthy pass once the primary is ejected.
priorities_http: [2]u8,
/// Each cluster's endpoints as options state them: the address with its
/// #174 weight and #396 tier folded in.
endpoint_options_l4: [1]zoxy.Options.Cluster.Endpoint,
endpoint_options_http: [2]zoxy.Options.Cluster.Endpoint,
clusters: [2]zoxy.Options.Cluster,
/// The catch-all, behind #417's guarded route — a longer prefix carrying
/// a route-phase policy, which only the `route_policy_reject` script
/// reaches — and #434's handler route, which answers `/handled` itself.
routes_http: [5]zoxy.Options.Listener.Route,
request_filters_http: [12]zoxy.Options.Listener.Filter,
/// The #175 response rules beside them: the always-on stamp the client
/// oracle requires on every proxied 200, and the 5xx rule whose edit
/// must never appear (the scripted origin answers no 5xx).
response_filters_http: [4]zoxy.Options.Listener.ResponseFilter,
/// On an http draw the plaintext listener's two routes, guarded route
/// included — a terminator runs the http chain whole.
routes_tls: [5]zoxy.Options.Listener.Route,
listener_options: [3]zoxy.Options.Listener,
/// How many of `listener_options` this seed actually binds: two on a
/// plaintext seed, three when it drew TLS clients (§4).
listeners_count: u8,
/// The seed's config, stated as options (#417) and resolved by the
/// library's own `config.resolve` — so every seed's config is held to
/// every rule a file or a custom build is.
options: zoxy.Options,
config: zoxy.config.Config,
origin: Origin,
origin_http: HttpOrigin,
clients: [clients_max]EchoClient,
l7_clients: [clients_max]HttpClient,
/// The HTTP/2 population (#275): h2c clients on the http listener, drawn
/// from the same coin flips as the HTTP/1.1 ones on a seed that speaks it.
h2_clients: [clients_max]H2Client,
h2_count: u8,
/// The HTTP/3 population (#449): QUIC clients to the terminating
/// listener's binding, on a seed whose terminating listener speaks http
/// and drew one. Drawn from `h3_prng`, so no other draw of a seed moves.
h3_clients: [h3_clients_max]H3Client,
h3_count: u8,
/// The admin plane's population (§8): scrapers of the metrics listener,
/// on a seed that binds one. From the arena, since each holds a whole
/// response; drawn from a stream of their own, so no other draw moves.
admin_scrapers: []AdminScraper,
/// #275: what the http cluster's origins speak — HTTP/1.1 to `origin_http`
/// on most seeds, HTTP/2 to `h2_origin` on the rest, in the clear or over
/// TLS to the origin fixture. Drawn from a stream of its own.
http_protocol: zoxy.Options.Cluster.Protocol,
h2_origin: H2Origin,
/// #296: on a seed whose http cluster speaks HTTP/1.1, the origin may be
/// behind TLS: `https_origin` answers, under the origin fixture's leaf.
http_tls: bool,
https_origin: HttpsOrigin,
/// #481: on a seed that draws it, the L4 cluster follows a name its two
/// scripted nameservers answer — the origin, and on an adversarial seed
/// later the refusing address beside it — and each answers by a drawn
/// behaviour, under the datagram adversary.
dns_l4: bool,
dns_zone: zoxy.testing.Zone,
dns_phases: [2]zoxy.testing.Zone.Phase,
dns_behaviors: [2]zoxy.testing.Behavior,
dns_names: [1]zoxy.Options.Cluster.Dns.Name,
nameservers: [2]Nameserver,
/// §8: on a seed whose http cluster speaks HTTP/2, a third of an HTTP/2
/// client's declared POSTs are gRPC calls its origin never answers, so the
/// proxy's deadline answers them. Their own stream.
grpc_prng: std.Random.DefaultPrng,
/// §7: what the HTTP/2 origin answers the http cluster's gRPC health
/// check with, on a seed that draws one.
grpc_health: ?zoxy.http.h2.Answer,
/// RFC 9113 §6.5.2's SETTINGS an exchange client opens with: its own
/// stream, so the tuning moves no other draw.
h2_tuning_prng: std.Random.DefaultPrng,
/// RFC 9113's violations (`H2Mode.violations`): which exchange clients
/// break the protocol once instead, each owed a stated answer. Its own
/// stream, so the floods and plans draw as they did.
h2_violation_prng: std.Random.DefaultPrng,
/// #434 over HTTP/2: which h2c streams ask the build's handler route
/// rather than the origin. Its own stream, so the plans draw as they did.
h2_handler_prng: std.Random.DefaultPrng,
/// Which shape the HTTP/2 origin answers each request in, drawn per
/// request on clean seeds too (`pickH2Answer`), and how many of each it
/// staged whole.
h2_shape_prng: std.Random.DefaultPrng,
h2_shapes_answered: [h2_origin_shapes.len]u32,
quic_http: bool,
quic_connections: u32,
h3_prng: std.Random.DefaultPrng,
/// The §4 terminating population (#125) and its credentials. Held on the
/// harness because the server borrows the table for its life, and because
/// a `Credentials` owns a libcrypto key that `tearDown` must free — the
/// arena cannot, it is not arena memory.
tls_clients_storage: [tls_client_slots]TlsClient,
/// How many terminating clients the seed drew — what sizes the engine
/// pool — against how many storage slots are in use, which the #204
/// resuming client makes one larger the moment it starts.
tls_clients: u8,
tls_clients_live: u8,
/// Whether the resuming client has started, and the key material it
/// starts with. Drawn up front from the scenario stream rather than when
/// it starts: the draw then sits at a fixed point in that stream instead
/// of one the delivery order chooses.
tls_resume_started: bool,
tls_resume_seeds: [3][32]u8,
/// Set when the wind-down begins, so nothing dials a listener that has
/// stopped accepting.
scenario_ended: bool,
/// What the terminating listener speaks once the handshake hands over.
tls_protocol: zoxy.config.Config.Listener.Protocol,
/// What each terminating client sends, distinct per client so the echo
/// oracle can tell one session's bytes from another's. Read only by the
/// l4 draw; an http terminator sends its script's request instead.
tls_tokens: [tls_client_slots][tls_token_bytes]u8,
/// The script each terminating client sends over an http terminator
/// (#215), one per storage slot including the resuming client's. Drawn
/// rather than fixed so the filter, redirect, static, rejection and
/// sticky paths ride the transform too — the population used to send one
/// POST-then-GET pair, which exercised the response render's happy path
/// and nothing else.
tls_scripts: [tls_client_slots]l7.Script,
/// Each slot's ALPN offer (#271), drawn beside its script and read by the
/// same two places: `startTlsClient` to make the offer, and
/// `verifyTlsSessions` to hold the outcome to what the listener implies.
tls_alpn_offers: [tls_client_slots]TlsAlpnOffer,
/// HTTP/2 over the terminating listener (#271, §7): on a seed whose http
/// listener speaks HTTP/2 and whose terminator is http, half have it offer
/// `h2` after HTTP/1.1. A slot that offers `h2` alone is then served
/// HTTP/2 over its session, by an exchange `tls_h2_clients` writes and
/// judges, where any other offer is still answered HTTP/1.1. Its own
/// stream, so no other draw moves.
tls_h2: bool,
tls_h2_prng: std.Random.DefaultPrng,
tls_h2_clients: [tls_client_slots]H2Client,
/// Streams the HTTP/2 TLS slots heard answered whole, for the census.
tls_h2_streams: u32,
tls_credentials: [3]?zoxy.tls.Credentials,
/// #297: on a seed that draws it, the terminating listener holds two more
/// certificates beside its default — a P-384 one and a second P-256 one —
/// and each TLS slot names one of them, the default's, an unknown name, or
/// nothing, so the choice a ClientHello's name makes is swept.
tls_sni: bool,
/// #298: the L4 listener's SNI table on a seed that draws one, and what
/// each L4 client opened with (null for a silent one, or no table).
l4_sni: bool,
l4_sni_routes: [2]zoxy.Options.Listener.SniRoute,
l4_sni_route_count: u8,
l4_hello_kinds: [clients_max]?HelloKind,
l4_sni_prng: std.Random.DefaultPrng,
tls_names: [tls_client_slots][]const u8,
/// #411: the signature schemes each TLS slot's hello offers — every one
/// zssl knows, but on a #297 seed narrowed to one key type or one curve —
/// so the listener's choice between key types is swept, and so is the
/// refusal of an offer no certificate the name reaches can sign under.
tls_scheme_offers: [tls_client_slots]zoxy.tls.SchemeOffer,
/// #297 over QUIC: the name each HTTP/3 client's hello asks for.
h3_names: [h3_clients_max][]const u8,
tls_sni_credentials: [sni_certificates.len]?zoxy.tls.Credentials,
tls_certificate_choices: [sni_choices_count]zoxy.tls.certificate_set.Choice,
tls_certificate_sets: [3][]const zoxy.tls.certificate_set.Choice,
/// #304: on a seed that draws it, the terminating listener asks every
/// client for a certificate chaining to the client CA — optionally or
/// requiring one — and each TLS slot presents nothing, the leaf that CA
/// signed, or a leaf from another CA, which must be refused.
tls_client_verify: ?zoxy.Options.Listener.ClientVerify,
tls_client_presents: [tls_client_slots]ClientPresents,
tls_client_identities: [2]?zoxy.tls.Credentials,
/// Slots the client CA turned away, as the TLS verdict found them.
tls_client_refusals: u32,
/// How many handshakes were shown each choice, as the TLS and HTTP/3
/// verdicts found them: the census's proof that every certificate was
/// chosen by a name.
tls_choices_shown: [sni_choices_count]u32,
/// #411: TLS slots turned away for an offer no certificate the name
/// reaches signs under, as the TLS verdict found them — each a failed
/// handshake the census does not hold against the proxy.
tls_scheme_refusals: u32,
/// The #142 gate drawn for the l4 listener; `populateClients` reads it
/// to decide whether its clients open with headers.
proxy_protocol_l4: ?zoxy.config.Config.Listener.ProxyProtocol,
/// The #142 send half drawn for the l4 cluster; the origin double then
/// expects and strips a header on every connection, and `verify` holds
/// what it heard against what the clients were (`verifyUpstreamIdentities`).
proxy_protocol_send_l4: ?zoxy.config.Config.Cluster.ProxyProtocolSend,
/// Per-L4-client address its header announced (len 0 = none): distinct
/// per client, so `verifyAccessLog` can demand the log states each one
/// on clean seeds — presence is attribution.
l4_announced: [clients_max][announced_bytes_max]u8,
l4_announced_len: [clients_max]u8,
/// The same announcement as an address (valid where `l4_announced_len`
/// is nonzero), for the #142 send-identity oracle — text serves the log
/// needle, this serves `IpAddress.eql`.
l4_announced_address: [clients_max]std.Io.net.IpAddress,
/// The L4 clients whose header announced them from `denied_network`
/// (#425): the connection policy's to refuse, once the header is read.
l4_denied_count: u8,
l4_count: u8,
l7_count: u8,
clients_count: u8,
ended_count: u8,
/// Clean seeds run without the adversary and with a well-behaved
/// origin, so the L7 oracles demand exact golden outcomes.
clean: bool,
/// The seed drew the #178 cookie-keyed http cluster: the pick is
/// forced to `hash` on `canon.sticky_cookie_name`, every L7 client
/// runs the stamp oracle, and `verify` holds the sticky counters to
/// the responses they annotate.
sticky_http: bool,
/// The #181 dial-retry budget on the http cluster; zero on the seeds
/// that carry no second endpoint, which is most of them.
retries_http: u16,
/// The seed allows the #180 upgrade token on its http listener, and has
/// a tunnel pool to carry it. Off on most seeds, so the handshake script
/// keeps proving the `501` every config had before the feature.
upgrades_http: bool,
/// The seed's #236 request-body cap on the plaintext http listener; `0`
/// on every clean seed, since a `413` is a status its scripts did not ask
/// for.
max_body_bytes: u64,
/// The #237 keep-alive request cap this run's http listener carries.
/// On the listener since the freeze (#305), so the harness derives it
/// beside the body cap rather than into `limits`.
keepalive_requests: u32,
/// The size each relay buffer's halves are cut to (§5), the default but
/// on a third of adversarial seeds (`deriveRelayBufferBytes`).
relay_buffer_bytes: u32,
/// The seed's http origin prefixes an interim `100 Continue` to every
/// answer (#232). Drawn once per seed rather than per accept, so a clean
/// seed's transcript stays exact — which is the point: the golden oracle
/// is what has teeth over the interim path, and it only runs on clean
/// seeds.
interim_http: bool,
tunnels: u32,
/// The seed's http listener takes h2c (#275), and has the HTTP/2 pools to
/// serve it: sessions and the shared streams they multiplex. Off on some
/// seeds, so the plaintext listener keeps proving HTTP/1.1 alone; small on
/// a share of adversarial ones, so the session and stream sheds fire.
h2c_http: bool,
h2_connections: u32,
stream_slots: u32,
/// Rapid Reset may be among the seed's floods (#276). Drawn with the pools
/// rather than with the client, because each stream it resets is an
/// access-log line, a hundred of them as fast as PONGs come back — past
/// what an adversary's slow sink drains through any staging but the
/// largest. Such a seed stages at the ceiling, which holds every line.
h2_rapid_reset: bool,
/// Decided before `io.init` (the ring the sim registers must equal the
/// limit the server accounts against — Server.init asserts the match),
/// consumed by `startServerAndOrigins` for the rest of the pool shape.
force_exhaustion: bool,
head_buffers: u32,
end_timer_completion: SimIo.Completion,
/// Virtual instant at which the HTTP origin stops listening mid-run, or
/// 0 for never. Drawn on a fraction of checked-http adversarial seeds:
/// probes then start refusing while parked connections from earlier
/// exchanges still exist, which is the only schedule that reaches the
/// §5 parked-close on ejection under the fuzz — chance alone almost
/// never lines an ejection up with a parked conn. Statistical, not
/// guaranteed: a scenario that winds down before the drawn instant
/// never sees its outage, which is fine — the sweep needs the schedule
/// to land often, not on every draw.
http_origin_stop_at_ns: u64,
/// Whether this seed steps the wall clock past a sealing key's rotation
/// interval (#202), and whether it has. Drawn only on seeds that
/// terminate TLS: a plaintext seed seals no ticket, so a jump there would
/// move nothing while shifting the whole sweep's stream position.
clock_jump_wanted: bool,
clock_jumped: bool,
/// Where this seed strands an op, or null for the seeds that strand none
/// (#206) — and, once one has been taken at the wind-down, which kind it
/// was. Separate fields for the reason the pair above is two: what a seed
/// drew and what it did are different facts, and `verify` needs the
/// second to decide whether a stuck drain was asked for. The kind is
/// never part of the draw; both modes take what the schedule armed rather
/// than what a die named (`drawStrandKind`, `armDropNext`).
drop_mode: ?DropMode,
drop_kind: ?SimIo.OpKind,
/// Whether the teardown mode's latch has been armed, so the second
/// wind-down a scenario can have does not arm it twice.
drop_latch_armed: bool,
http_origin_stop_completion: SimIo.Completion,
/// #428's churn: on seeds whose http cluster carries the refusing
/// endpoint, two updates mid-run swap it for a second refusing address
/// and back, reweighting the origin in place. Drawn on its own stream.
churn_http: bool,
churn_at_ns: [2]u64,
/// The two churn steps' timers.
churn_completions: [2]SimIo.Completion,
/// Churn steps run so far.
churn_steps_count: u8,
/// Virtual instant at which the drain begins, or 0 for "at the
/// scenario's end like every other seed".
///
/// Every seed already drains — `endScenario` calls `beginDrain` — but by
/// then the clients have finished, so the drain's two race-dependent
/// rungs stay out of reach: an accept completion already in flight when
/// the drain starts (`shed_draining`), and a connection still live when
/// the drain deadline fires (`drained_at_deadline`). Starting the drain
/// while the scenario is still working is what puts traffic in front of
/// it. Clean seeds never draw one — a drain is a legitimate reason to
/// miss a golden outcome, which is the thing those seeds exist to
/// forbid.
///
/// It is not free: a seed that stops accepting early serves less. Across
/// the 4096-seed sweep this costs about 6% of the client work
/// (`accepted` 12599 → 11858, `l7_responses` 2234 → 2119) and a quarter
/// of the probes, since a draining server stops the prober. Eight rungs
/// for 6% is the trade being made, and raising the draw rate would buy
/// coverage margin at a steeper one.
drain_at_ns: u64,
drain_completion: SimIo.Completion,
scenario_prng: std.Random.DefaultPrng,
/// #417's picker instances, one per cluster, and whether each cluster
/// selects its own this seed. Drawn from a stream of their own, so every
/// seed's scenario draws are the ones they were before pickers existed:
/// a seed that selects none runs exactly the sweep it always ran.
pickers: [2]zoxy.testing.ScriptedPicker,
picker_l4: bool,
picker_http: bool,
/// #417's listener policy, on every seed and on every listener that runs
/// the http filter chain: it refuses `l7.canon.policy_prefix`, which only
/// the `policy_reject` script asks for, and proceeds with every other
/// request — so every L7 exchange of the sweep passes through it. It
/// tags each one `policy_tag` (#433).
policy_listener: zoxy.testing.ScriptedPolicy,
/// #437's consulting policy, after it on both http listeners: it asks the
/// http cluster about the requests `consult_get` sends, and the HTTP/2
/// streams that ask the same (`drawH2Plan`), and fails open, so the
/// adversary's breakage leaves those requests `get`'s outcomes.
policy_consult: zoxy.testing.ScriptedConsultOpenPolicy,
policy_selections: [2]zoxy.extension.Selection,
/// #434's handler, on a route of both http chains: it answers what it
/// is routed, and never flips its flag, so every answer is predictable.
handler: zoxy.testing.ScriptedHandler,
/// #436's check kind, on the L4 cluster when `l4Check` draws it: rounds
/// the echo origin sends back.
probe_l4: zoxy.testing.ScriptedProbe,
/// Which check the L4 cluster's draw becomes (#436), from its own stream
/// so no other draw moves: see `l4Check`.
probe_l4_coin: u8,
/// Which of the HTTP/2 population's GETs consult (#437), from its own
/// stream for the same reason: see `drawH2Plan`.
h2_consult_prng: std.Random.DefaultPrng,
/// #424's response policy, on every http listener: it adds a header to
/// every response head and holds each to carrying the listener's tag.
response_policy: zoxy.testing.ScriptedResponsePolicy,
response_policy_selections: [1]zoxy.extension.Selection,
/// #425's connection policy, on every listener: it refuses the L4
/// clients whose PROXY header announces them from `denied_network`, and
/// lets on every other connection.
connection_policy: zoxy.testing.ScriptedConnectionPolicy,
connection_policy_selections: [1]zoxy.extension.Selection,
/// #417's route-phase policy, on the guarded route of both http chains.
/// It holds every request it sees to carrying the listener's tag.
policy_route: zoxy.testing.ScriptedPolicy,
route_policy_selections: [1]zoxy.extension.Selection,

/// The tag the listener policy sets (#433), and which the route policy
/// and the http cluster's picker require: every L7 exchange of the sweep
/// passes the listener's policy first, so every later view must carry it
/// — across a retry and a replay too, which evaluate no policy again.
const policy_tag: u64 = 0x0433_7a6f_7879_0433;
/// The tag the connection policy sets on every connection it lets on
/// (#425): an l4 connection's pick and line carry it, and every http
/// request reaches the listener's request policy carrying it.
const connection_tag: u64 = 0x0425_7a6f_7879_0425;

fn bindAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
}

fn httpBindAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8081") catch unreachable;
}

/// The §4 terminating listener (#125). Its own socket rather than TLS on
/// one of the two above, so a seed that draws it changes what reaches
/// *this* port and nothing about the plaintext coverage beside it.
fn tlsBindAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8443") catch unreachable;
}

fn originAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
}

fn httpOriginAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9001") catch unreachable;
}

/// The #181 second endpoint: an address no origin ever binds, so every
/// dial to it is refused by `SimIo.finishConnect`'s own listener lookup
/// rather than by an adversary roll. That is the issue's motivating
/// failure modelled exactly — one endpoint of a cluster refusing while
/// the others are healthy — and it is refused on *clean* seeds too, so
/// the retry path is reached by the seeds whose oracles demand exact
/// outcomes rather than only by the ones that tolerate a cut.
///
/// Dead rather than merely slow on purpose: a black-holed endpoint would
/// time out, and a timed-out dial does not retry (it has spent the
/// budget a retry carries). Dead rather than a second live origin also
/// keeps every oracle untouched — nothing here can serve, so every
/// response the clients check still came from the one origin at index 0,
/// including the #178 sticky tag pinned to its address.
fn refusingEndpointAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9002") catch unreachable;
}

/// The refusing endpoint's stand-in while the #428 churn has it away:
/// another address nothing listens at.
fn churnRefusingAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9003") catch unreachable;
}

pub fn setUp(harness: *Harness, arena: std.mem.Allocator, seed: u64) !void {
    // Scenario shape and Io schedule use *separate* streams from one
    // seed, so harness decisions never perturb delivery order.
    harness.scenario_prng = std.Random.DefaultPrng.init(seed ^ 0x5a5a5a5a5a5a5a5a);
    const random = harness.scenario_prng.random();
    harness.drawPickers(seed);
    // #428: its own stream, as the pickers', so the shared one is unmoved.
    var churn_prng = std.Random.DefaultPrng.init(seed ^ 0x0428_0428_0428_0428);
    const churn = churn_prng.random();
    harness.churn_http = churn.boolean();
    harness.churn_at_ns = .{
        (10 + churn.uintAtMost(u64, 30)) * std.time.ns_per_ms,
        (50 + churn.uintAtMost(u64, 30)) * std.time.ns_per_ms,
    };
    // #436: its own stream, as the pickers', so the shared one is unmoved.
    var probe_prng = std.Random.DefaultPrng.init(seed ^ 0x0436_0436_0436_0436);
    harness.probe_l4_coin = probe_prng.random().uintLessThan(u8, probe_coin_sides);
    harness.h2_consult_prng = std.Random.DefaultPrng.init(seed ^ 0x0437_0437_0437_0437);
    // #449: its own stream too, for the HTTP/3 draws and the datagram
    // adversary's, which no seed before it drew.
    harness.h3_prng = std.Random.DefaultPrng.init(seed ^ 0x0449_0449_0449_0449);
    harness.policy_listener = .{
        .reject_prefix = l7.canon.policy_prefix,
        .tag = policy_tag,
        .expect_tag = connection_tag,
        // #430: the guarded route is chosen by name, and tagged as well.
        .route_prefix = l7.canon.guarded_prefix,
        .route_name = l7.canon.guarded_route_name,
        // #424: every request it hands on carries a header of its own,
        // through every render — the first try, a retry and a replay.
        .edits = &.{.{ .add = .{ .name = "X-Scripted-Policy", .value = "listener" } }},
    };
    harness.policy_consult = .{ .cluster_name = http_cluster_name, .consult_prefix = l7.canon.consult_prefix };
    harness.policy_selections = .{
        zoxy.extension.select(runtime.extensions.request_policies, &harness.policy_listener),
        zoxy.extension.select(runtime.extensions.request_policies, &harness.policy_consult),
    };
    // The route's policy answers with its own 403 page (#431), where the
    // listener's rejects from the static set: one arm per phase.
    harness.policy_route = .{ .answer_prefix = l7.canon.route_policy_path, .expect_tag = policy_tag };
    harness.route_policy_selections = .{
        zoxy.extension.select(runtime.extensions.request_policies, &harness.policy_route),
    };
    harness.response_policy = .{
        .edits = &.{.{ .add = .{ .name = "X-Scripted-Response", .value = "listener" } }},
        .expect_tag = policy_tag,
    };
    harness.response_policy_selections = .{
        zoxy.extension.select(runtime.extensions.response_policies, &harness.response_policy),
    };
    harness.connection_policy = .{ .refuse_network = denied_network, .tag = connection_tag };
    harness.handler = .{ .toggles = false };
    harness.connection_policy_selections = .{
        zoxy.extension.select(runtime.extensions.connection_policies, &harness.connection_policy),
    };

    // A quarter of seeds run clean: adversary off, origin
    // well-behaved, so the L7 golden oracles demand each script's
    // exact outcome — a silently dropped 400 or a shed that should
    // not happen fails the seed instead of passing as a "cut".
    harness.clean = random.uintLessThan(u8, 4) == 0;
    // A quarter of adversarial seeds shrink the pools to force the §8
    // rungs. Drawn here rather than in `startServerAndOrigins` because
    // the head-buffer ring is the Io backend's to register, and its size
    // must be settled before the backend exists. 1–3 ring buffers, so
    // across the sweep some seeds shed at the ring (1: a second
    // concurrent head finds it empty) and others get far enough to shed
    // at the relay rung instead (2–3: heads bind, the deeper rungs
    // starve) — one size would shadow one rung or the other.
    harness.force_exhaustion = !harness.clean and random.uintLessThan(u8, 4) == 0;
    harness.head_buffers = if (harness.force_exhaustion)
        1 + random.uintLessThan(u32, 3)
    else if (harness.clean)
        // The clean-seed watermark margin, same as the clean-seed pools
        // in `deriveInitOptions`.
        clean_pool_capacity
    else
        2 * clients_max;
    try harness.io.init(arena, .{
        .seed = seed,
        .adversary = withDatagramAdversary(
            deriveAdversary(random, harness.clean),
            harness.h3_prng.random(),
            harness.clean,
        ),
        .buffer_group_count = harness.head_buffers,
        // #206: a stranded seed reaches the §8 give-up on purpose, and
        // the operator forensics it prints there are two hundred lines
        // apiece. The sweep's verdict is `abortedWith`, not the wording,
        // and a gate whose output scrolls is a gate nobody reads.
        .dump_on_abort = false,
    });
    // A third of seeds have every stream client dial from an IPv6 peer,
    // so the §7 forwarded-for line, the access log and a #142 header the
    // proxy writes from an observed client meet the other family. Its own
    // stream, so the shared one is unmoved.
    var family_prng = std.Random.DefaultPrng.init(seed ^ 0x0006_0006_0006_0006);
    harness.io.client_ip6 = family_prng.random().uintLessThan(u8, 3) == 0;
    // Which cause the sim reports for every failure it injects (§8).
    // Production reads it off an errno; a virtual socket table has none,
    // so the scenario states one — and drawing it per seed is what makes
    // four of the five `kernel_pressure_*` cause counters reachable at
    // all: under the fixed `out_of_buffers` default that one counter
    // carried every injected failure of a 4096-seed sweep and the other
    // four stayed at zero. A clean seed injects nothing, so it keeps the
    // default rather than choosing a cause it will never report.
    if (!harness.clean) {
        harness.io.setPressureCause(random.enumValue(Io.Pressure.Cause));
    }
    harness.drain_at_ns = deriveDrainAt(harness.clean, random);
    harness.drawSni(seed);
    harness.drawL4Sni(seed);
    harness.drawHttpProtocol(seed);
    harness.drawDns(seed);
    try harness.drawClientCa(arena, seed);
    harness.deriveTopology(random);
    try harness.drawAdmin(arena, seed);
    try harness.startServerAndOrigins(arena, random);
    harness.injectOneShotFaults(random);
    harness.populateClients(random);

    harness.armScenarioTimers();
}

/// The three timers a scenario runs on: the force-end that outlives any
/// stuck work, the optional early drain, and the optional origin outage.
/// Split from `setUp` when the #206 drop pushed that one past the length
/// limit — the same remedy `deriveTopology` took twice before it.
///
/// Every one is armed *after* the population exists, so nothing can fire
/// against a half-built scenario, and every optional one asserts it lands
/// before the force-end — a timer scheduled past that is a timer whose
/// scenario is already over.
fn armScenarioTimers(harness: *Harness) void {
    harness.end_timer_completion = .{};
    harness.io.timerStart(
        &harness.end_timer_completion,
        scenario_end_ns,
        Harness,
        harness,
        onScenarioEnd,
    );
    harness.drain_completion = .{};
    if (harness.drain_at_ns != 0) {
        assert(harness.drain_at_ns < scenario_end_ns);
        harness.io.timerStart(
            &harness.drain_completion,
            harness.drain_at_ns,
            Harness,
            harness,
            onDrainStart,
        );
    }
    harness.armChurn();
    harness.http_origin_stop_completion = .{};
    if (harness.http_origin_stop_at_ns != 0) {
        assert(harness.http_origin_stop_at_ns < scenario_end_ns);
        harness.io.timerStart(
            &harness.http_origin_stop_completion,
            harness.http_origin_stop_at_ns,
            Harness,
            harness,
            onHttpOriginStop,
        );
    }
}

/// One of the two optional deadlines a scenario may arm, or 0 for "off".
///
/// A third of seeds arm each, over a range that straddles the connect and
/// idle timeouts drawn alongside them — so an armed one sometimes fires
/// inside a dial, sometimes mid-exchange, and sometimes never, all under
/// the adversary. The two callers share this because they share the
/// question; what differs is the clock each hangs off, which is what
/// their call sites say.
fn deriveOptionalDeadlineMs(random: std.Random) u32 {
    if (random.uintLessThan(u8, 3) != 0) return 0;
    const deadline_ms = 10 + random.uintAtMost(u32, 90);
    assert(deadline_ms >= 10);
    assert(deadline_ms <= 100);
    return deadline_ms;
}

/// When the drain starts, for the seeds that start one early.
///
/// Bimodal, because the two rungs want opposite instants and one window
/// cannot serve both. `shed_draining` needs the drain inside the opening
/// accept burst, while sockets are still queued — a millisecond in.
/// `drained_at_deadline` needs the drain to arrive after an exchange has
/// begun, with a deadline short enough to still find it running (see
/// `drain_deadline_ms` below, which is the other half of reaching it).
///
/// The split is load-bearing, not decoration: replacing it with one
/// uniform 0.1-150 ms window drops `shed_draining` to 1 and 0 per 1024
/// seeds from two starts — a census failure — while leaving
/// `drained_at_deadline` untouched at 23-24.
fn deriveDrainAt(clean: bool, random: std.Random) u64 {
    if (clean) return 0;
    if (random.uintLessThan(u8, 4) != 0) return 0;
    const at_ns = if (random.boolean())
        100_000 + random.uintAtMost(u64, 3 * std.time.ns_per_ms)
    else
        (10 + random.uintAtMost(u64, 140)) * std.time.ns_per_ms;
    assert(at_ns >= 100_000);
    assert(at_ns < scenario_end_ns);
    return at_ns;
}

/// How long the drain gives its stragglers (§8).
///
/// A deadline long enough that the drain always finishes first is a
/// deadline that never reaps, and `drained_at_deadline` stays
/// unreachable however the drain itself is timed — measured: at the
/// fixed 100 ms the timer delivered on 54 of 400 seeds and found every
/// connection already tearing down. Seeds that drain early therefore
/// sometimes draw one short enough to still find work running, which is
/// a setting production operators tune too. Seeds that drain only at the
/// scenario's end keep the roomy default: there is nothing left to reap
/// by then, and a short deadline would say nothing about it.
///
/// A minority draw 0 — "no cap" (§5), the shape a config that names no
/// deadline gets, where `beginDrain` arms no timer at all and the drain
/// ends only when the last connection does. Kept a minority on purpose:
/// those seeds cannot reach `drained_at_deadline`, and that rung's
/// census margin is already the thinnest in the gate.
fn deriveDrainDeadlineMs(drain_at_ns: u64, random: std.Random) u32 {
    assert(drain_at_ns < scenario_end_ns);
    if (drain_at_ns == 0) return 100;
    if (random.uintLessThan(u8, 4) == 0) return 0;
    if (!random.boolean()) return 100;
    const deadline_ms = 1 + random.uintAtMost(u32, 4);
    assert(deadline_ms >= 1);
    return deadline_ms;
}

/// The drawn mid-scenario drain (§8). `beginDrain` is idempotent, so the
/// scenario-end drain that follows is a no-op rather than a second one.
fn onDrainStart(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    harness.server.beginDrain();
    harness.armTeardownStrand();
}

/// The one-shot faults the sweep would otherwise never pull (§9).
///
/// `SimIo` carries an injector for each — the set-option one exists
/// precisely because "64 seeds stayed green because nothing could make
/// the call fail" — but until now no seed called either, so the paths
/// they reach stayed as unreachable as they were before the injectors
/// were written. Adversarial seeds only: a fault is the wrong thing to
/// hand a seed whose oracle is an exact golden outcome.
///
/// A pending set-option fault is claimed by whoever makes the next
/// `setNodelay`/`setLingerRst` call, and that is not always the server:
/// an origin double closing in reset mode makes one too. The first
/// version of this function assumed the server always got there first
/// and panicked the sweep on the seed that proved otherwise, which is
/// why both doubles now absorb the error instead of taking it as
/// `unreachable`. A fault landing on a double costs that origin its RST
/// and nothing else, and the server still claims most of them: it calls
/// `setNodelay` on every admission and every upstream dial, far earlier
/// and far oftener than a double reaches a reset-mode close. Measured,
/// since the split is the part worth doubting rather than asserting —
/// `kernel_pressure_set_option` lands 232-265 times per 1024 seeds
/// against roughly 288 faults drawn.
fn injectOneShotFaults(harness: *Harness, random: std.Random) void {
    assert(harness.server.listeners.len >= 1);
    assert(harness.server.listeners.len <= harness.listener_options.len);
    if (harness.clean) return;
    if (random.uintLessThan(u8, 4) == 0) {
        const faults = 1 + random.uintAtMost(u8, 1);
        for (0..faults) |_| harness.io.injectSetOptionError();
    }
    // An accept that fails backs the listener off by
    // `accept_retry_delay_ms` and retries; the queued socket keeps its
    // place, so no client is lost to this — it costs the scenario ten
    // milliseconds of its two seconds.
    if (random.uintLessThan(u8, 4) == 0) {
        const index = random.uintLessThan(usize, harness.server.listeners.len);
        harness.io.injectAcceptError(harness.server.listeners[index].listener);
    }
}

/// The mid-run origin outage (§7): refused dials are a fate clients
/// already meet under the adversary's own knobs, so the prefix oracles
/// absorb it — what it adds is probes failing against a cluster that
/// still holds parked connections.
fn onHttpOriginStop(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    // Whichever origin answers at the http endpoint (#275, #296).
    if (harness.http_protocol.http2()) {
        harness.h2_origin.stopListening();
    } else if (harness.http_tls) {
        harness.https_origin.stopListening();
    } else {
        harness.origin_http.stopListening();
    }
}

/// The #428 churn's two updates, when this seed churns: only a cluster
/// that carries the refusing endpoint, so the swap is one refusing
/// address for another, and only one whose retry budget outlasts both
/// refusing addresses, so any pick that lands on either falls back to the
/// origin — which is what keeps every golden outcome what it was, a
/// reweight's moved hash placements included. The invariant is
/// `churns`': a budget of at least two retries, and it says why one is
/// not enough.
fn armChurn(harness: *Harness) void {
    harness.churn_completions = .{ .{}, .{} };
    harness.churn_steps_count = 0;
    if (!harness.churns()) return;
    for (&harness.churn_completions, harness.churn_at_ns) |*completion, at_ns| {
        assert(at_ns < scenario_end_ns);
        harness.io.timerStart(completion, at_ns, Harness, harness, onChurn);
    }
}

/// Whether this seed churns its http cluster's endpoints.
///
/// Only with two retries or more. A request whose tries straddle a churn
/// step can meet both refusing addresses: refused by the one the step
/// sends away, then by its stand-in, which it never tried and so does not
/// skip. One retry then answers `502`, and a clean seed's golden outcome
/// forbids that. Soak #146's seed 567398787 is exactly that: an HTTP/3
/// request (#449), its handshake putting it at 10 ms, where the first
/// step fell. Two retries leave the origin a try, and one request's tries
/// — refusals land at once, since a clean seed dials with no delay —
/// cannot straddle both steps, which fall at least 10 ms apart
/// (`churn_at_ns`).
fn churns(harness: *const Harness) bool {
    if (harness.endpoints_http_count == 2) assert(harness.retries_http >= 1);
    return harness.churn_http and harness.endpoints_http_count == 2 and harness.retries_http >= 2;
}

/// One churn step. The first sends the refusing endpoint away for a
/// second refusing address and reweights the origin; the second brings
/// the first back — into its own draining slot while anything still
/// holds it, or a freed one — and the origin's weight with it. A step may
/// land on a server already draining: an update during shutdown is one a
/// control plane can send, and the sweep holds it to the same oracles.
fn onChurn(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    const step: u8 = harness.churn_steps_count;
    harness.churn_steps_count += 1;
    assert(harness.churn_steps_count <= harness.churn_completions.len);
    const origin = harness.endpoint_options_http[0];
    const refusing = harness.endpoint_options_http[1];
    // The harness draws weights from 1, so neither is drained.
    assert(origin.weight >= 1);
    assert(refusing.weight >= 1);
    const away: std.Io.net.IpAddress = if (step == 0) churnRefusingAddress() else refusing.address.ip;
    const weight_max = zoxy.constants.endpoint_weight_max;
    const stepped: u16 = if (origin.weight < weight_max) origin.weight + 1 else origin.weight - 1;
    const origin_weight = if (step == 0) stepped else origin.weight;
    assert(origin_weight >= 1);
    const set = [_]zoxy.extension.EndpointSet.Endpoint{
        .{ .address = origin.address.ip, .weight = origin_weight, .priority = origin.priority },
        .{ .address = away, .weight = refusing.weight, .priority = refusing.priority },
    };
    // Valid by construction: distinct nonzero ports (9000, 9002, 9003),
    // weights in 1..256, tiers 0 or 1. Room by construction, resting on
    // `endpoint_slots = 3`: step 0 has one arrival and one free slot; step
    // 1's arrival either rejoins its draining slot or takes the one
    // `reclaim` freed — never both short.
    harness.server.replaceEndpoints(http_cluster_index, &set) catch unreachable;
}

fn deriveAdversary(random: std.Random, clean: bool) SimIo.Adversary {
    if (clean) {
        return .{ .partial_io = false };
    }
    return .{
        .partial_io = true,
        .connect_delay_ns_max = random.uintAtMost(u64, 5_000_000),
        .connect_refuse_percent = random.uintAtMost(u8, 20),
        // A blackholed dial hangs until the connect deadline — the §8
        // dial-timeout 504 path, exercised under schedule fuzz.
        .connect_blackhole_percent = random.uintAtMost(u8, 10),
        .reset_percent = random.uintAtMost(u8, 10),
        .kernel_pressure_percent = random.uintAtMost(u8, 8),
        // Dial-time kernel pressure (§8): the witnessKernelPressure
        // sites on both dial paths were unreachable under every seed
        // until this fate existed (issue #106, kind B).
        .connect_pressure_percent = random.uintAtMost(u8, 5),
        // A sink that has fallen behind (§8): the resume-a-short-write and
        // stalled-drain paths, under schedule fuzz. Most seeds keep it
        // instant; some stall it past a whole scenario.
        //
        // It does *not* reach the drop rung, whatever a stall's length: a
        // scenario emits single-digit lines against staging buffers
        // holding ~130, so there is nothing to overflow. The sweep's
        // census names `access_log_dropped` as uncovered for exactly that
        // reason, and src/access_log_test.zig drives the burst instead.
        .log_write_stall_ns = if (random.uintLessThan(u8, 4) == 0)
            random.uintAtMost(u64, 200_000_000)
        else
            0,
    };
}

/// The datagram adversary (#449), drawn from the HTTP/3 stream so the
/// rest of the adversary stays as every seed drew it: drops and
/// duplicates, deliveries delayed past their successors, octets corrupted
/// — which an AEAD must refuse, where the stream adversary never corrupts
/// — and a source port rebound, as a NAT would. It touches only datagram
/// sockets, so a seed with no QUIC binding meets none of it.
fn withDatagramAdversary(adversary: SimIo.Adversary, random: std.Random, clean: bool) SimIo.Adversary {
    if (clean) return adversary;
    var drawn = adversary;
    drawn.udp_drop_percent = random.uintAtMost(u8, 15);
    drawn.udp_duplicate_percent = random.uintAtMost(u8, 10);
    drawn.udp_corrupt_percent = random.uintAtMost(u8, 5);
    drawn.udp_delay_ns_max = random.uintAtMost(u64, 3_000_000);
    drawn.udp_rebind_percent = if (random.uintLessThan(u8, 8) == 0) random.uintAtMost(u8, 3) else 0;
    assert(drawn.udp_drop_percent <= 100);
    return drawn;
}

/// The HTTP/3 draw (#449), from its own stream: half the seeds whose
/// terminating listener speaks http give it a QUIC binding on the same
/// port, and one or two HTTP/3 clients. A starved seed holds one QUIC
/// slot, so a second client meets the Retry the pool's pressure earns
/// and then the rung behind it.
fn deriveHttp3(harness: *Harness) void {
    const random = harness.h3_prng.random();
    harness.quic_http = false;
    harness.h3_count = 0;
    harness.quic_connections = 0;
    if (harness.tls_clients == 0) return;
    if (harness.tls_protocol != .http) return;
    if (!random.boolean()) return;
    harness.quic_http = true;
    harness.h3_count = 1 + random.uintLessThan(u8, h3_clients_max);
    // The HTTP/3 clients present no certificate, so a listener requiring
    // one (#304) would refuse every one of them and leave their oracle
    // nothing to judge: such a seed's client CA is optional instead.
    if (harness.tls_client_verify == .required) harness.tls_client_verify = .optional;
    const starved = !harness.clean and random.uintLessThan(u8, 3) == 0;
    harness.quic_connections = if (starved) 1 else @as(u32, harness.h3_count) + 1;
    // Its exchanges run on the shared streams HTTP/2's do.
    const streams: u32 = if (starved) 1 else @as(u32, harness.h3_count) * H3Client.streams_max;
    harness.stream_slots += streams;
    assert(harness.stream_slots <= SimIo.stream_slots_max);
    assert(harness.quic_connections >= 1);
}

/// An http chain's route table (#417): the guarded route and the #434
/// handler route ahead of the catch-all — the order resolving sorts them
/// into anyway, the longer prefixes first.
fn httpRoutes(harness: *Harness) [5]zoxy.Options.Listener.Route {
    assert(harness.route_policy_selections.len == 1);
    assert(l7.canon.guarded_prefix.len > 1);
    const handler = zoxy.extension.select(runtime.extensions.handlers, &harness.handler);
    return .{
        // #302's predicates, each with an answer a script would notice.
        // The guarded route asks for a header every script under it
        // sends, so a header test that missed would lose the route's
        // policy; the handler's asks for the host every script under it
        // names, so a host test that missed would send it to the origin.
        .{
            .prefix = l7.canon.guarded_prefix,
            .header = .{ .name = "host", .predicate = .present },
            .cluster = http_cluster_name,
            .request_policies = &harness.route_policy_selections,
            .name = l7.canon.guarded_route_name,
        },
        // #434: answered by the build's own handler, no cluster at all.
        .{ .host = l7.canon.script_host, .prefix = l7.canon.handler_prefix, .handler = handler },
        // Decoys: the root prefix, which every request meets, and a host
        // or a header value no request carries. Either test misfiring
        // hands every request to the handler.
        .{ .host = decoy_host, .prefix = "/", .handler = handler },
        .{
            .prefix = "/",
            .header = .{ .name = l7.canon.log_request_header, .predicate = .{ .equals = decoy_value } },
            .handler = handler,
        },
        .{ .prefix = "/", .cluster = http_cluster_name },
    };
}

/// A host and a header value no client of the sweep sends: what the
/// decoy routes and filters match on, and must never meet.
const decoy_host = "decoy.sim.test";
const decoy_value = "never";

/// #177's client prefixes for the http listeners, whose peer is always
/// `SimIo`'s 198.51.100.1 or 2001:db8:1::1 — PROXY headers are the l4
/// listener's alone. Any-of, so the first, which no client is in, is
/// judged a miss before the next holds: a rule carrying these holds for
/// every request those listeners see.
const sweep_client_prefixes = [_]zoxy.Options.Listener.Cidr{
    .{ .address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 0 }, .port = 0 } }, .prefix_len = 24 },
    .{ .address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 0 }, .port = 0 } }, .prefix_len = 24 },
    .{ .address = .{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0 } }, .prefix_len = 32 },
};

/// A substring of `script_host`, for a `contains` the scripts meet.
const script_host_fragment = "im";

comptime {
    assert(std.mem.indexOf(u8, l7.canon.script_host, script_host_fragment) != null);
}

/// Prefixes none of the sweep's clients come from, one per family.
const decoy_client_prefixes = [_]zoxy.Options.Listener.Cidr{
    .{ .address = .{ .ip4 = .{ .bytes = .{ 10, 66, 0, 0 }, .port = 0 } }, .prefix_len = 16 },
    .{ .address = .{ .ip6 = .{ .bytes = .{ 0xfd, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 0 } }, .prefix_len = 16 },
};

/// Methods no script, HTTP/2 or HTTP/3 client sends.
const decoy_methods: std.EnumSet(zoxy.Options.Listener.Method) = blk: {
    var set: std.EnumSet(zoxy.Options.Listener.Method) = .{};
    set.insert(.put);
    set.insert(.delete);
    set.insert(.patch);
    break :blk set;
};

/// The one method the filtered scripts send.
const get_only: std.EnumSet(zoxy.Options.Listener.Method) = blk: {
    var set: std.EnumSet(zoxy.Options.Listener.Method) = .{};
    set.insert(.get);
    break :blk set;
};

const l4_cluster_name = "origin-l4";
/// Its place in `harness.clusters`: the L4 cluster is the first.
const l4_cluster_index: u16 = 0;
const http_cluster_name = "origin-http";
/// The http cluster's place in the options, after the l4 one.
const http_cluster_index: u16 = 1;

/// Whether each cluster selects its #417 picker this seed: a quarter of
/// seeds for the l4 cluster and half for the http one, independently,
/// from a stream apart from the scenario's. The http half is wider
/// because its rarest completion — a parked connection found stale
/// (#423) — needs a picker seed that also meets a stale checkout, and a
/// quarter left it to the luck of one script table's shape (#434).
/// The picker answers by the entropy zoxy hands it, so across a sweep it
/// names every slot and, now and then, one past the end — the fallback.
fn drawPickers(harness: *Harness, seed: u64) void {
    var picker_prng = std.Random.DefaultPrng.init(seed ^ 0x0417_0417_0417_0417);
    const random = picker_prng.random();
    harness.pickers = @splat(.{ .choice = .by_entropy });
    // The http cluster's picks all carry a request the listener's policy
    // tagged; an l4 pick, the tag its connection policy set (#425).
    harness.pickers[0].expect_tag = connection_tag;
    harness.pickers[1].expect_tag = policy_tag;
    harness.picker_l4 = random.uintLessThan(u8, 4) == 0;
    harness.picker_http = random.uintLessThan(u8, 4) <= 1;
    assert(harness.pickers[0].calls == 0);
    assert(harness.pickers[1].calls == 0);
}

/// The cluster's pick: its picker instance when this seed selects one,
/// otherwise the built-in policy it drew — drawn either way, so the
/// scenario stream stays where it was.
fn pickerOr(
    harness: *Harness,
    index: u1,
    selects: bool,
    drawn: zoxy.Options.Cluster.Pick,
) zoxy.Options.Cluster.Pick {
    assert(drawn != .extension);
    if (!selects) return drawn;
    const selection = zoxy.extension.select(runtime.extensions.pickers, &harness.pickers[index]);
    assert(selection.index == 0);
    return .{ .extension = selection };
}

/// A stock policy, drawn: one draw whichever it is. `hash` keys on the
/// client's address here; the cookie key is `deriveSticky`'s.
fn randomPick(random: std.Random) zoxy.Options.Cluster.Pick {
    return switch (random.enumValue(zoxy.config.Config.Cluster.Pick.Builtin)) {
        .rr => .rr,
        .p2c => .p2c,
        .hash => .{ .hash = .source_ip },
    };
}

/// The #181 draw: a third of seeds give the http cluster a retry budget
/// and, with it, the refusing second endpoint the budget exists to get
/// past. The two ride together deliberately — a dead endpoint without
/// retries would answer half the requests `502`, which a clean seed's
/// golden outcomes forbid, while retries without one would be a budget
/// nothing ever spends.
///
/// Drawn across the whole legal range rather than fixed at 1, because
/// the two ways a retry can end are decided by which of the budget and
/// the endpoint set runs out first: at 1 retry a second failure answers
/// `502` with the budget spent, while at 2 or more it is the *endpoints*
/// that run out and the answer comes from the exhaustion rung instead.
/// Both are reachable here only because the range is.
/// A pool-starved seed keeps the single-endpoint topology whatever it
/// drew, and the reason is a shadow the §9 census depends on. Those seeds
/// set `relay_buffers` and `upstream_slots` both to 1, and the exemption
/// for `l7_shed_upstream_slots` rests on the L7 path taking the relay
/// buffer first, so the relay rung answers everything that would reach
/// the slot rung. A *second endpoint* breaks that: the one slot can be
/// parked on endpoint 0 while a request picks endpoint 1, which cannot
/// reuse it and must dial — a correct shed, and one no single-endpoint
/// cluster can produce, because there the parked connection is always the
/// one wanted. Found on seed 4316 of a 16384-seed sweep. A consult (#437)
/// reaches that rung by a road of its own: it holds the one slot with no
/// relay buffer, so a request beside it passes the relay rung. The behavior
/// itself is covered directly by `src/http_proxy_test.zig`, which
/// exhausts the upstream pool on purpose; what does not belong here is a
/// pool-sizing scenario arriving as a side effect of a retry draw.
fn deriveRetries(harness: *Harness, random: std.Random) void {
    // Drawn either way, so a starved seed's stream position stays where
    // an unstarved one's is and the suppression costs no other coverage.
    const budget: u16 = if (random.uintLessThan(u8, 3) == 0)
        1 + random.uintAtMost(u16, zoxy.constants.cluster_retries_max - 1)
    else
        0;
    // An HTTP/2 cluster (#275) retries nothing (`ClusterRetriesOnHttp2`):
    // a request is a stream on a shared connection, not a dial of its own.
    if (budget == 0 or harness.force_exhaustion or harness.http_protocol != .http1) {
        harness.retries_http = 0;
        harness.endpoints_http_count = 1;
        return;
    }
    harness.retries_http = budget;
    harness.endpoints_http_count = 2;
    harness.endpoints_http[1] = .{ .ip = refusingEndpointAddress() };
    assert(harness.retries_http >= 1);
    assert(harness.retries_http <= zoxy.constants.cluster_retries_max);
}

/// The #180 draw: a third of seeds allow the WebSocket token and size a
/// tunnel pool for it. The rest keep the `501` — which is not merely the
/// absence of coverage but the other half of the gate, and the shape
/// every config written before the feature still has.
///
/// A clean seed's pool is wide enough that no handshake can be shed,
/// because its oracle demands an exact transcript and a `503` is not the
/// answer its script asked for — the same reason `deriveMaxInflight`
/// caps only under the adversary. An adversarial seed draws a pool small
/// enough to run out, which is what reaches the §8 tunnel rung.
fn deriveUpgrades(harness: *Harness, random: std.Random) void {
    // Drawn either way, so the stream after it is unmoved; an upgrade has
    // no HTTP/2 origin to tunnel to (`ClusterH2cWithUpgrades`), nor a TLS
    // one (`ClusterTlsWithUpgrades`), so a seed whose http cluster speaks
    // either (#275, #296) takes none.
    const drawn = random.uintLessThan(u8, 3) == 0;
    if (!drawn or harness.http_protocol != .http1 or harness.http_tls) {
        harness.upgrades_http = false;
        harness.tunnels = 0;
        return;
    }
    harness.upgrades_http = true;
    // One tunnel under the adversary, so two concurrent handshakes
    // collide and the §8 rung is reached by ordinary scheduling rather
    // than by a rare coincidence. A clean seed gets room for every
    // client instead: its oracle demands an exact transcript, and a
    // `503` is not the answer its script asked for.
    harness.tunnels = if (harness.clean) clients_max else 1;
    assert(harness.tunnels >= 1);
    assert(harness.tunnels <= clients_max);
}

/// Whether the terminating listener speaks HTTP/2 too (`tls_h2`), and the
/// room its sessions need. An `h2` TLS session takes an HTTP/2 session
/// slot as an h2c one does, so a seed with room for every h2c client's
/// streams gets room for every TLS slot's as well; a starved one keeps
/// its starved pools, which are its coverage.
fn deriveTlsH2(harness: *Harness) void {
    harness.tls_h2_streams = 0;
    const drawn = harness.tls_h2_prng.random().boolean();
    harness.tls_h2 = drawn and harness.tls_protocol == .http and harness.h2c_http and harness.tls_clients >= 1;
    if (!harness.tls_h2) return;
    if (harness.h2_connections < clients_max) return; // Starved.
    harness.h2_connections += tls_client_slots;
    harness.stream_slots += @as(u32, tls_client_slots) * H2Client.streams_max;
    assert(harness.stream_slots <= SimIo.stream_slots_max);
}

/// Whether TLS slot `index` is served HTTP/2 (`tls_h2`): it offers `h2`
/// alone, on a listener that now speaks it.
fn slotSpeaksH2(harness: *const Harness, index: usize) bool {
    assert(index < tls_client_slots);
    return harness.tls_h2 and harness.tls_alpn_offers[index] == .h2_only;
}

/// The exchange an HTTP/2 TLS slot sends: `drawH2Plan`'s streams, their
/// bodies held so the whole flight is one TLS record (`sendApplicationData`
/// seals one at a time), from `tls_h2_prng`. No pacing — a throttle's held
/// credit, a flood — since the session sends the flight in one write.
fn prepareTlsH2Client(harness: *Harness, index: u8) void {
    assert(harness.slotSpeaksH2(index));
    const random = harness.tls_h2_prng.random();
    const client = &harness.tls_h2_clients[index];
    client.* = .{};
    const streams = 1 + random.uintLessThan(u8, H2Client.streams_max);
    var plans: [H2Client.streams_max]l7.H2Plan = @splat(.{});
    for (plans[0..streams]) |*plan| {
        plan.* = drawH2Plan(random, random);
        if (!plan.carriesBody()) continue;
        plan.body_len = @min(plan.body_len, tls_h2_body_bytes_max);
        plan.frames = @intCast(@min(@as(u32, plan.frames), plan.body_len));
        assert(plan.frames >= 1);
    }
    // Salts past every h2c client's, so no two bodies on the origin match.
    const salt: u8 = clients_max + index;
    client.prepare(&harness.io, tlsBindAddress(), plans[0..streams], salt, harness.clean, .exchange, .{});
    client.interim_owed = harness.interimOwed();
    assert(client.flight().len <= zoxy.constants.tls_record_plaintext_bytes_max);
}

/// An HTTP/2 TLS slot's verdict: what came back over the session is
/// judged as an h2c client's socket would be — every frame whole, each
/// stream answered at most once with a status its script allows and a
/// canonical body, and on a clean seed every stream a whole `200` — by the
/// client that wrote the exchange. True when the session heard any of it.
fn verifyTlsH2(harness: *Harness, client: *const TlsClient, index: usize, back: []const u8) !bool {
    assert(harness.slotSpeaksH2(index));
    const exchange = &harness.tls_h2_clients[index];
    exchange.adoptTranscript(back);
    try exchange.verify();
    if (back.len >= 1 and client.handshake_done) {
        // Answered over HTTP/2, so `h2` was what the listener chose.
        const selected = client.alpnSelected() orelse return error.TlsAlpnSelectionDiverged;
        if (!std.mem.eql(u8, selected, "h2")) return error.TlsAlpnSelectionDiverged;
    }
    harness.tls_h2_streams += exchange.streamsAnswered();
    return back.len >= 1;
}

/// An HTTP/2 TLS slot's largest POST body: four of them, their heads and
/// the preface well inside one record.
const tls_h2_body_bytes_max: u32 = 1024;

fn deriveHttp2(harness: *Harness, random: std.Random) void {
    if (random.uintLessThan(u8, 4) == 0) {
        harness.h2c_http = false;
        harness.h2_connections = 0;
        harness.stream_slots = 0;
        harness.h2_rapid_reset = false;
        return;
    }
    harness.h2c_http = true;
    harness.h2_rapid_reset = random.boolean();
    // A clean seed has room for every client's every stream, so its golden
    // oracle never meets a shed; an adversarial one is sometimes starved to
    // one session and a stream or two.
    const starved = !harness.clean and random.uintLessThan(u8, 3) == 0;
    // Starved: one session, so a second h2c client is turned away, or two
    // over a stream or two, so the shared pool runs out while each
    // session's own advertisement still has room.
    harness.h2_connections = if (starved) 1 + random.uintLessThan(u32, 2) else clients_max;
    harness.stream_slots = if (starved)
        1 + random.uintLessThan(u32, 2)
    else
        @as(u32, clients_max) * H2Client.streams_max;
    assert(harness.stream_slots <= SimIo.stream_slots_max);
    assert(harness.h2_connections >= 1);
}

fn deriveTopology(harness: *Harness, random: std.Random) void {
    harness.endpoints_l4 = .{.{ .ip = originAddress() }};
    harness.endpoints_http = .{
        .{ .ip = httpOriginAddress() },
        .{ .ip = httpOriginAddress() },
    };
    deriveRetries(harness, random);
    deriveUpgrades(harness, random);
    deriveHttp2(harness, random);
    harness.max_body_bytes = deriveMaxBodyBytes(harness.clean, random);
    harness.keepalive_requests = deriveKeepaliveRequests(harness.clean, random);
    harness.relay_buffer_bytes = deriveRelayBufferBytes(harness.clean, harness.l4_sni, random);
    // A quarter of seeds. Clean ones included, deliberately: an
    // adversarial seed only holds the transcript to a legal *prefix*, so
    // a proxy that settled on the interim and dropped the real answer
    // would pass there. The exact-outcome oracle is the one that notices.
    harness.interim_http = random.uintLessThan(u8, 4) == 0;
    // Each cluster draws its pick policy independently so mixed configs
    // (one cluster each way) flow through the balancer under the schedule
    // fuzz, not just the uniform pairings. Single-endpoint clusters
    // short-circuit every policy identically today; the draw is pre-wired
    // coverage for a multi-endpoint topology. `hash` rides here for what
    // the *scenario* can exercise — the pick path, the health mask, and
    // the L4/L7 plumbing of the client address — while the properties it
    // exists for (stickiness, minimal disruption on ejection) are pinned
    // by `balancer.zig`'s own tests, which can hold thousands of distinct
    // clients against a multi-endpoint cluster as a scenario cannot.
    const pick_l4 = harness.pickerOr(0, harness.picker_l4, randomPick(random));
    const http_hash_key = deriveSticky(harness, random);
    // A sticky cluster keeps `hash`: its cookie is what the scripts check.
    // Every other seed's hash keys on the client's address.
    assert(harness.sticky_http or http_hash_key == .source_ip);
    const pick_http: zoxy.Options.Cluster.Pick = if (harness.sticky_http)
        .{ .hash = http_hash_key }
    else
        harness.pickerOr(1, harness.picker_http, randomPick(random));
    // Each cluster draws §7 active health checks independently, so the
    // prober runs its whole lifecycle — sweeps, fall/rise transitions
    // under the adversary's connect fates, parked-close on ejection, and
    // drain from every state — inside the schedule fuzz. Fail-open keeps
    // a single-endpoint topology's routing unchanged whatever the
    // verdicts, so the L7 golden oracles hold on clean seeds and
    // prefix-legality holds under the adversary. A dial check passes on a
    // clean seed; a build's check kind on the L4 cluster (#436) may not,
    // since the L4 origin draws its modes on every seed — which fail-open
    // makes harmless.
    const connect_timeout_ms: u32 = 20 + random.uintAtMost(u32, 40);
    const health = deriveHealthChecks(harness.clean, random, connect_timeout_ms, harness.probeShape());
    harness.grpc_health = health.grpc_health;
    harness.http_origin_stop_at_ns = health.http_origin_stop_at_ns;
    harness.proxy_protocol_send_l4 = deriveProxyProtocolSend(random);
    // #174 weights on a single-endpoint topology: the share itself is
    // moot (there is nobody to share against, and one endpoint at any
    // nonzero weight routes identically), but drawing a table at all
    // flows the weights contract — the nonzero-sum init assertion, the
    // eligibility filter's weight read — through the schedules the
    // adversary can produce. (A drawn weight of 1 everywhere is the
    // unweighted table, which resolving collapses to none: one seed in a
    // few hundred.) The proportional
    // properties are pinned by balancer.zig's own tests, exactly like
    // `hash`'s stickiness above.
    harness.weights_l4 = .{1 + random.uintAtMost(u16, 255)};
    // #396's tiers, assigned rather than defaulted: the harness is built
    // `undefined`, so a field default would never apply.
    harness.priorities_http = .{ 1, 0 };
    harness.weights_http = .{
        1 + random.uintAtMost(u16, 255),
        1 + random.uintAtMost(u16, 255),
    };
    wireClusters(harness, random, .{
        .l4 = pick_l4,
        .http = pick_http,
    }, health);
    harness.routes_http = harness.httpRoutes();
    harness.proxy_protocol_l4 = deriveProxyProtocol(random);
    harness.deriveTerminatingDraws(random);
    harness.deriveHttp3();
    harness.wireListeners(deriveForwarded(random));
    harness.deriveServerConfig(random, connect_timeout_ms, health.interval_ms);
}

/// The picks the two clusters were drawn with, bundled so `wireClusters`
/// takes one argument for them rather than two positional ones that
/// read alike at the call site.
const ClusterPicks = struct {
    l4: zoxy.Options.Cluster.Pick,
    http: zoxy.Options.Cluster.Pick,
};

/// The two cluster records, split from `deriveTopology` for exactly the
/// reason `deriveTerminatingDraws` below was: the #181 second endpoint
/// pushed that function past the length limit again. Nothing moved but
/// the braces — the literal is still evaluated where it was, so the four
/// draws inside it (a weights coin and a `max_inflight` per cluster) keep
/// their stream positions.
fn wireClusters(
    harness: *Harness,
    random: std.Random,
    picks: ClusterPicks,
    health: HealthDraw,
) void {
    assert(harness.endpoints_http_count >= 1);
    assert(harness.endpoints_http_count <= harness.endpoints_http.len);
    const l4_max_inflight = deriveMaxInflight(harness.clean, random);
    const http_max_inflight = deriveMaxInflight(harness.clean, random);
    harness.clusters[0] = harness.l4Cluster(random, picks.l4, health, l4_max_inflight);
    harness.clusters[1] = harness.httpCluster(random, picks.http, health, http_max_inflight);
    // The retry budget and the endpoint that makes it spendable ride
    // together (`deriveRetries`), so neither is ever configured alone.
    assert((harness.retries_http == 0) == (harness.endpoints_http_count == 1));
}

/// The L4 cluster's check (#436): its drawn dial, or on half the checked
/// seeds a build's check kind speaking two rounds the echo origin sends
/// back — and on an eighth of adversarial ones a script past the round
/// bound, the only way to reach `health_probe_rounds_exhausted`. Never
/// where the origin is owed a PROXY header (#142): it then requires one
/// on every connection, and a probe sends none.
fn l4Check(harness: *Harness, health: HealthDraw) ?Check {
    assert(harness.probe_l4_coin < probe_coin_sides);
    harness.probe_l4 = .{};
    var check = health.check_l4 orelse return null;
    if (harness.proxy_protocol_send_l4 != null) return check;
    if (harness.probe_l4_coin < probe_coin_kind) return check;
    const exhausts = harness.probe_l4_coin == probe_coin_exhausts and !harness.clean;
    harness.probe_l4 = .{ .rounds = if (exhausts) &probe_rounds_past_bound else &probe_rounds };
    if (!exhausts) assert(harness.probe_l4.rounds.len <= zoxy.constants.health_check_rounds_max);
    check.kind = .{ .extension = zoxy.extension.select(runtime.extensions.probes, &harness.probe_l4) };
    assert(check.kind == .extension);
    return check;
}

/// `probe_l4_coin`'s faces: below `probe_coin_kind` the dial stays; the
/// rest draw the kind, and `probe_coin_exhausts` the script past the bound.
const probe_coin_sides: u8 = 8;
const probe_coin_kind: u8 = probe_coin_sides / 2;
const probe_coin_exhausts: u8 = probe_coin_kind;

/// A greeting and a ping, each echoed.
const probe_rounds = [_][]const u8{ "zoxy-probe-hello\n", "zoxy-probe-ping\n" };
/// One round more than `health_check_rounds_max` allows.
const probe_rounds_past_bound = [_][]const u8{ "1\n", "2\n", "3\n", "4\n", "5\n" };

comptime {
    assert(probe_rounds_past_bound.len > zoxy.constants.health_check_rounds_max);
    assert(probe_coin_exhausts >= probe_coin_kind);
    assert(probe_coin_exhausts < probe_coin_sides);
}

/// The l4 cluster. Its draws — a weights coin, the panic threshold, slow
/// start, the cluster cap — come in the order the record always drew
/// them, so every seed's stream stays where it was.
fn l4Cluster(
    harness: *Harness,
    random: std.Random,
    pick: zoxy.Options.Cluster.Pick,
    health: HealthDraw,
    max_inflight: ?u32,
) zoxy.Options.Cluster {
    const weighted = random.boolean();
    const ejects = health.check_l4 != null or health.passive_l4 != null;
    const panic_threshold_percent = derivePanicThreshold(random, ejects);
    const slow_start_ms = deriveSlowStart(random, max_inflight, ejects);
    const max_total_inflight = deriveMaxInflight(harness.clean, random);
    harness.endpoint_options_l4 = .{.{
        .address = harness.endpoints_l4[0],
        .weight = if (weighted) harness.weights_l4[0] else 1,
    }};
    assert(harness.endpoint_options_l4[0].weight >= 1);
    assert(max_total_inflight == null or !harness.clean);
    return .{
        .name = l4_cluster_name,
        .endpoints = &harness.endpoint_options_l4,
        .pick = pick,
        .check = harness.l4Check(health),
        .passive_ejection = health.passive_l4,
        .panic_threshold_percent = panic_threshold_percent,
        .max_inflight = max_inflight,
        .slow_start_ms = slow_start_ms,
        .max_total_inflight = max_total_inflight,
        .proxy_protocol_send = harness.proxy_protocol_send_l4,
        // #481: a cluster following a name holds its IP literals alone in
        // `endpoints`, and the origin arrives as the name's first answer.
        .dns = if (harness.dns_l4) .{
            .names = &harness.dns_names,
            // The loader's floor (`dns_refresh_ms_min`): several rounds
            // in a 2 s scenario, the first after the 20 ms move.
            .refresh_min_ms = zoxy.constants.dns_refresh_ms_min,
            .refresh_max_ms = 4 * zoxy.constants.dns_refresh_ms_min,
            .addresses_max = 2,
        } else null,
    };
}

/// The http cluster, on the same terms: a weights coin, a tiers coin on a
/// two-endpoint seed, the panic threshold, slow start, the cluster cap,
/// and the #393 retry budget, in the record's own order.
fn httpCluster(
    harness: *Harness,
    random: std.Random,
    pick: zoxy.Options.Cluster.Pick,
    health: HealthDraw,
    max_inflight: ?u32,
) zoxy.Options.Cluster {
    const count = harness.endpoints_http_count;
    const weighted = random.boolean();
    const tiered = count == 2 and random.boolean();
    const ejects = health.check_http != null or health.passive_http != null;
    const panic_threshold_percent = derivePanicThreshold(random, ejects);
    const slow_start_ms = deriveSlowStart(random, max_inflight, ejects);
    const max_total_inflight = deriveMaxInflight(harness.clean, random);
    // #393: a budget of one or two retry dials on half the adversary
    // seeds that retry, so concurrent clients meet it, and the leak
    // invariant holds every permit back by the scenario's end. Never on a
    // clean seed: a budget turns a retry into a `502`, which its golden
    // transcript forbids — the reason `max_inflight` stays off them too.
    const retry_budget: ?u16 = if (!harness.clean and harness.retries_http >= 1 and random.boolean())
        1 + random.uintAtMost(u16, 1)
    else
        null;
    for (harness.endpoint_options_http[0..count], 0..) |*endpoint, index| {
        endpoint.* = .{
            .address = harness.endpoints_http[index],
            .weight = if (weighted) harness.weights_http[index] else 1,
            .priority = if (tiered) harness.priorities_http[index] else 0,
        };
    }
    assert(count <= harness.endpoint_options_http.len);
    return .{
        .name = http_cluster_name,
        .endpoints = harness.endpoint_options_http[0..count],
        .pick = pick,
        .check = health.check_http,
        .passive_ejection = health.passive_http,
        .panic_threshold_percent = panic_threshold_percent,
        .max_inflight = max_inflight,
        .slow_start_ms = slow_start_ms,
        .max_total_inflight = max_total_inflight,
        .retries = .{ .count = harness.retries_http, .budget = retry_budget },
        // #428: room for the set and the one endpoint draining out of it.
        .endpoint_slots = if (harness.churns()) 3 else null,
        .protocol = harness.http_protocol,
        .tls = if (harness.http_protocol == .h2 or harness.http_tls)
            .{ .server_name = zoxy.tls.testdata.origin_host_name, .ca_pem = zoxy.tls.testdata.origin_ca_pem }
        else
            null,
    };
}

/// The §4 terminating draws, split from `deriveTopology` when the #202
/// clock jump pushed that one past the length limit — the same reason,
/// and the same remedy, as `deriveServerConfig`.
///
/// Order is load-bearing rather than incidental: everything here is drawn
/// from the scenario stream, and `deriveClockJump` deliberately draws
/// nothing when the seed took no terminating clients, so a plaintext
/// seed's stream position — and with it every plaintext seed's coverage —
/// stays exactly where it was before any of this existed.
fn deriveTerminatingDraws(harness: *Harness, random: std.Random) void {
    // The terminating listener rides the l4 cluster's endpoint but keeps
    // its own route, so `verifyUpstreamIdentities` can tell a terminated
    // connection's origin conn from a plaintext one's.
    harness.tls_protocol = if (random.boolean()) .http else .l4;
    // An http terminator runs the plaintext http chain's routes; an l4
    // one relays to the l4 cluster, which its listener names directly.
    harness.routes_tls = harness.httpRoutes();
    harness.tls_clients = deriveTlsClients(
        random,
        harness.proxy_protocol_send_l4,
        harness.force_exhaustion,
    );
    harness.listeners_count = if (harness.tls_clients >= 1) 3 else 2;
    for (&harness.tls_scripts) |*script| {
        const drawn = l7.scripts.terminating_scripts[
            random.uintLessThan(usize, l7.scripts.terminating_scripts.len)
        ];
        // The same clean-seed exclusion the plaintext draw makes, and for
        // the same reason — see `drawScript`.
        script.* = if (harness.clean and drawn == .dribbled_head) .get else drawn;
    }
    harness.clock_jump_wanted = deriveClockJump(harness.tls_clients, random);
    harness.drop_mode = deriveDropMode(harness.clean, random);
    // Last, so the draws above keep the values each seed always gave them.
    for (&harness.tls_alpn_offers) |*offer| {
        offer.* = random.enumValue(TlsAlpnOffer);
    }
    harness.deriveTlsH2();
    assert(harness.listeners_count <= harness.listener_options.len);
    assert(harness.tls_clients >= 1 or !harness.clock_jump_wanted);
}

/// The top-level options draw — the timeouts, the deadlines, and the
/// access-log coin — split from `deriveTopology` when the #178 draw
/// pushed that one past the length limit; the cluster and listener
/// tables it points at are the caller's, already wired. The options are
/// resolved by `startServerAndOrigins`, once the arena exists.
fn deriveServerConfig(
    harness: *Harness,
    random: std.Random,
    connect_timeout_ms: u32,
    health_interval_ms: u32,
) void {
    assert(connect_timeout_ms >= 1);
    assert(health_interval_ms >= 1);
    // Drawn *above* the dial budget rather than independently: resolving
    // refuses the other order (§5), so an independent draw would spend
    // seeds on a config production cannot load.
    const idle_timeout_ms = connect_timeout_ms + 10 + random.uintAtMost(u32, 70);
    // In the order the draws have always come, so every seed keeps its
    // stream positions.
    const head_ms = deriveHeadTimeoutMs(harness.clean, random, connect_timeout_ms, idle_timeout_ms);
    const drain_deadline_ms = deriveDrainDeadlineMs(harness.drain_at_ns, random);
    // The §6 age cap: measured from the connection's birth, so the clamp
    // sometimes reaps an actively-relaying connection.
    const max_lifetime_ms = deriveOptionalDeadlineMs(random);
    // The §8 per-exchange deadline: measured from routing instead, so the
    // same range lands on a different clock.
    const request_ms = deriveOptionalDeadlineMs(random);
    // Three seeds in four run with the access log on, so the sink, its
    // staging swap, and the per-request captures all take the schedule
    // fuzz; the fourth leaves it off, which is the shape that must
    // reserve nothing and read no clock (§5, §8).
    const access_log_on = random.uintLessThan(u8, 4) != 0;
    harness.options = .{
        // The terminating listener is the third, and only a seed that drew
        // TLS clients binds it. Sliced rather than left inert so a
        // plaintext seed's fd, ring and listener budgets are exactly what
        // they were before TLS existed.
        .listeners = harness.listener_options[0..harness.listeners_count],
        .clusters = &harness.clusters,
        .timeouts = .{
            .connect_ms = connect_timeout_ms,
            .idle_ms = idle_timeout_ms,
            .head_ms = head_ms,
            // Stated, not drawn: drawing it would move every seed's stream
            // position for a clock whose coverage is the tunnels' own.
            .tunnel_ms = zoxy.defaults.timeouts.tunnel_ms,
            .health_interval_ms = health_interval_ms,
            .request_ms = request_ms,
            .max_lifetime_ms = max_lifetime_ms,
            .drain_deadline_ms = drain_deadline_ms,
            // #311's serving watchdog is off for the whole sweep: a tick
            // every second of virtual time would shift all 4096 schedules,
            // and the seeds that strand `.timer` reach the drain watchdog
            // that a serving one would answer instead. `server_test.zig`
            // provokes it and asserts the exit code.
            .loop_watchdog_ms = null,
        },
        .limits = harness.limitsStated(),
        // #140, on every seed with a log: two scripts send the request
        // header and the sized origin answers with the response one, so
        // both captures run under the whole schedule fuzz.
        .access_log = if (access_log_on) .{
            .sink = .stdout,
            .request_headers = &log_request_headers,
            .response_headers = &log_response_headers,
        } else null,
        // #159: a page for `403` on every seed, and the `respond` body. `503`
        // is deliberately left out: the sheds keep their empty bodies,
        // which is the opt-in rule stated as a property.
        .bodies = &bodies,
        .error_pages = &error_pages,
        .resolver = if (harness.dns_l4) .{ .nameservers = &nameserver_addresses, .timeout_ms = 20 } else null,
    };
}

/// The pools the options must state for this seed to resolve: tunnels
/// where a listener allows an upgrade, streams where one speaks HTTP/2 —
/// neither has a default. Every other pool is left to zoxy's rule.
///
/// What these size is not what the server runs with: the simulator hands
/// `Server.init` its own pool sizes (`deriveInitOptions`), because a
/// starved seed sizes them past what options may state — no tunnel for a
/// listener that allows upgrades, no session for one that speaks h2c —
/// and those rungs are the coverage it is starved for.
fn limitsStated(harness: *const Harness) zoxy.Options.Limits {
    const multiplexes = harness.h2c_http or harness.quic_http;
    const stated: zoxy.Options.Limits = .{
        .tunnels = if (harness.upgrades_http) harness.tunnels else null,
        .h2_streams = if (multiplexes) harness.stream_slots else null,
        .quic_connections = if (harness.quic_http) harness.quic_connections else null,
        // #275: an `h2` cluster's TLS connections share the engines' heap
        // (`LimitUpstreamH2TlsOverEngines`), and the default engine count
        // fills it alone. `Server.init`'s own count is drawn apart; this
        // is only what the loader is shown, so it fits beside them.
        .tls_engines = if ((harness.http_protocol == .h2 or harness.http_tls) and harness.tls_clients >= 1) 64 else null,
    };
    assert(!harness.upgrades_http or harness.tunnels >= 1);
    if (multiplexes) assert(harness.stream_slots >= 1);
    return stated;
}

/// The #178 draw: a quarter of seeds key the http cluster on the sim
/// cookie, forcing `hash` (a cookie key rides no other policy). The
/// rest draw their pick freely, where `hash` means source_ip — so both
/// hash keys, and every keyless policy, flow through the schedule fuzz.
/// The sticky scripts run on every seed either way; on a non-sticky one
/// their cookies are inert bytes, which is itself the oracle. Also
/// re-proves the pinned tag: what the scripts send and the client
/// oracle demands must be what the running mint spells for the one http
/// endpoint, so a hash change fails the sweep loudly instead of quietly
/// re-homing cookie holders.
fn deriveSticky(harness: *Harness, random: std.Random) zoxy.config.Config.Cluster.HashKey {
    harness.sticky_http = random.uintLessThan(u8, 4) == 0;
    var minted_tag: [zoxy.balancer.Balancer.endpoint_tag_len]u8 = undefined;
    zoxy.balancer.Balancer.formatEndpointTag(
        zoxy.balancer.Balancer.addressIdentity(&harness.endpoints_http[0]),
        &minted_tag,
    );
    assert(std.mem.eql(u8, &minted_tag, l7.canon.sticky_tag));
    assert(l7.canon.sticky_cookie_name.len >= 1);
    if (harness.sticky_http) {
        return .{ .cookie = l7.canon.sticky_cookie_name };
    }
    return .source_ip;
}

/// The §8 per-endpoint cap for one cluster, or null for uncapped.
///
/// Only adversarial seeds cap, and the reason is the oracle rather than
/// the mechanism: a refusal is a `503` an L7 script did not ask for and a
/// close an L4 client did not expect, both of which a clean seed's golden
/// outcomes forbid. Under the adversary they are ordinary fates — the
/// prefix oracles already tolerate a cut, and a cap-shed `503` is the
/// same shape as the pool-exhaustion one those seeds already produce.
///
/// The value is drawn *below* the client population on purpose. A cap
/// the scenario cannot reach exercises the comparison and nothing else;
/// at one or two against up to six clients, both refusal paths run
/// against real contention, and every seed still crosses back under the
/// cap as connections finish — so the recovery side runs too.
/// The #236 body cap, drawn only under the adversary and for the same
/// reason `deriveMaxInflight` caps only there: a `413` is a status an L7
/// script did not ask for, and a clean seed's golden outcomes forbid it.
/// Drawn in two ranges, because the cap has two rungs and a single range
/// only ever reaches one of them.
///
/// The **single-byte** range reaches the *answered* rung: `post_big`'s few
/// thousand bytes and `post_sized`'s twenty-four are over it on every
/// draw, and they are over it in the bytes coalesced with the head — so
/// the request is refused `413` before a byte is pumped.
/// `post_chunked`'s eight-byte payload is the one that is not — roughly
/// half the range leaves it under the cap — which is legal and which the
/// directed tests cover regardless.
///
/// The **kilobyte** range reaches the *streaming* rung, which the first
/// cannot. Cutting a body mid-stream needs three things at once: a body
/// whose head declares no length (a declared one is refused before a
/// byte is pumped), a cap the first delivery does not already exceed,
/// and a total that outgrows it later. `post_chunked_big` is the body,
/// and this range is the cap — starting just above the widest a single
/// delivery can be, so the first always passes under it, and staying a
/// kilobyte wide so it stays far below that script's six thousand.
/// The widest a single delivery can be: the simulator's default socket
/// ring, which this harness never widens. A cap at or above it cannot be
/// exceeded by the bytes that arrive alongside the head, whatever the
/// schedule chops them into.
const first_delivery_bytes_max: u64 = 4096;

/// How wide the streaming range is. Named because the two bounds below
/// are one claim, not two: the cap must land above every byte a first
/// delivery can carry and below what `post_chunked_big` sends, and a
/// script whose body stopped clearing that gap would make the streaming
/// rung silently unreachable rather than fail here.
const body_cap_stream_span: u64 = 1024;
comptime {
    assert(l7.scripts.chunked_big_body_bytes >
        first_delivery_bytes_max + body_cap_stream_span);
}

fn deriveMaxBodyBytes(clean: bool, random: std.Random) u64 {
    if (clean) return 0;
    if (random.uintLessThan(u8, 3) != 0) return 0;
    if (random.boolean()) {
        return first_delivery_bytes_max + random.uintLessThan(u64, body_cap_stream_span);
    }
    return 1 + random.uintLessThan(u64, 16);
}

/// The #237 keep-alive request cap. One or two, so `keepalive_pair` —
/// the script that sends a second request once the first settles
/// reusable — actually meets it: at one the first response announces the
/// close and the pair degrades to a single exchange, which its own spec
/// already allows for ("degrades to a single-exchange transcript when its
/// first response refuses reuse"), and at two it serves both and the
/// second is the one capped.
fn deriveKeepaliveRequests(clean: bool, random: std.Random) u32 {
    if (clean) return 0;
    if (random.uintLessThan(u8, 3) != 0) return 0;
    return 1 + random.uintLessThan(u32, 2);
}

/// The relay buffer's size (§5). The default on clean seeds, whose pools
/// are proved against it, and on two thirds of adversarial ones. The rest
/// draw it from the smallest the loader accepts up to the default, so
/// bodies and answers are pumped in more chunks than one. An HTTP/2
/// stream's DATA frame can then outrun its room and be held, and with it
/// its connection's input (#373). The default is the ceiling: a
/// terminating listener's relay buffer may be no larger than one TLS
/// record's plaintext. A seed that routes by SNI (#298) keeps the default:
/// its floor is that same record (`LimitRelayBufferUnderSniRouting`), and
/// the limits handed to `Server.init` here pass no loader that would say so.
fn deriveRelayBufferBytes(clean: bool, sni: bool, random: std.Random) u32 {
    const default = zoxy.constants.relay_buffer_bytes_default;
    const smallest = zoxy.constants.relay_buffer_bytes_min;
    if (clean) return default;
    if (sni) return default;
    if (random.uintLessThan(u8, 3) != 0) return default;
    const bytes = smallest + random.uintLessThan(u32, default - smallest + 1);
    assert(bytes >= smallest);
    assert(bytes <= default);
    return bytes;
}

/// The #235 head budget, drawn *apart* from the idle window on a third
/// of adversary seeds (#258).
///
/// It was pinned equal to `idle_timeout_ms` until the sweep had a client
/// that could reach it, and that was the right call at the time rather
/// than an oversight: with every head arriving whole, the two values
/// being equal cost nothing, while drawing them apart shifted every
/// seed's random stream to exercise an axis no seed could observe. The
/// issue measured exactly that — forcing every adversary seed to the
/// tightest legal budget changed nothing at all.
///
/// What changed is that `dribbled_head` now holds a head open and
/// `l7_head_budget_expired` witnesses the reap, so a tighter budget is a
/// genuinely different schedule rather than the same one wearing a
/// different number.
///
/// The band is the loader's own invariant, restated: strictly above
/// `connect_ms`, because a dial re-bases the deadline to that and a
/// budget beneath it would be spent before the hand-off; and never wider
/// than the window it exists to narrow.
fn deriveHeadTimeoutMs(
    clean: bool,
    random: std.Random,
    connect_ms: u32,
    idle_ms: u32,
) u32 {
    assert(connect_ms >= 1);
    assert(connect_ms < idle_ms);
    if (clean) return idle_ms;
    if (random.uintLessThan(u8, 3) != 0) return idle_ms;
    const span = idle_ms - connect_ms;
    assert(span >= 1);
    const drawn = connect_ms + 1 + random.uintLessThan(u32, span);
    assert(drawn > connect_ms);
    assert(drawn <= idle_ms);
    return drawn;
}

/// A cluster's #391 slow-start window: only where the loader allows one —
/// a cap to ramp and something to restore from — and then on half, short
/// enough that a restored endpoint's ramp runs out inside a scenario.
fn deriveSlowStart(random: std.Random, max_inflight: ?u32, ejects: bool) ?u32 {
    if (max_inflight == null or !ejects) return null;
    if (!random.boolean()) return null;
    const window_ms = 1 + random.uintAtMost(u32, 199);
    assert(window_ms >= 1 and window_ms <= 200);
    return window_ms;
}

fn deriveMaxInflight(clean: bool, random: std.Random) ?u32 {
    if (clean) return null;
    if (random.uintLessThan(u8, 3) != 0) return null;
    return 1 + random.uintAtMost(u32, 1);
}

/// Which check the http cluster runs, if any. An outage seed always
/// takes the dial check: its origin stops listening, so a request check
/// would only ever reach the same refused dial by a longer route.
fn checkHttpDraw(
    checked: bool,
    outage: bool,
    random: std.Random,
    tcp_check: Check,
    http_check: Check,
) ?Check {
    if (!checked) return null;
    if (outage) return tcp_check;
    return if (random.boolean()) http_check else tcp_check;
}

/// What a request check on the http cluster speaks: HTTP/1.1, gRPC's
/// health call (an HTTP/2 cluster), or nothing past the dial (HTTPS).
const ProbeShape = enum { http, grpc, dial };

/// An HTTP check is HTTP/1.1 in the clear: no HTTP/2 or HTTPS cluster
/// takes one (`ClusterH2cHttpCheck`, #296). An HTTP/2 cluster's request
/// check is gRPC's health call, over the origin pool (§7); an HTTPS
/// one's is the dial.
fn probeShape(harness: *const Harness) ProbeShape {
    if (harness.http_tls) {
        assert(harness.http_protocol == .http1);
        return .dial;
    }
    return if (harness.http_protocol.http2()) .grpc else .http;
}

/// The §7 health-check shape of one scenario: which clusters probe, how
/// fast, and whether the HTTP origin dies mid-run.
const HealthDraw = struct {
    check_l4: ?Check,
    check_http: ?Check,
    /// When the http cluster's check is a gRPC call, what the HTTP/2
    /// origin answers it with: SERVING, or on the quarter of request
    /// checks drawn to fail, NOT_SERVING.
    grpc_health: ?zoxy.http.h2.Answer,
    /// #230 passive ejection, drawn independently of the probes: the two
    /// compose rather than overlap, so a scenario must be able to run
    /// either alone as well as both.
    passive_l4: ?PassiveEjection,
    passive_http: ?PassiveEjection,
    interval_ms: u32,
    http_origin_stop_at_ns: u64,
};

const Check = zoxy.Options.Cluster.Check;
const PassiveEjection = zoxy.Options.Cluster.PassiveEjection;

/// A cluster's #390 panic threshold. Drawn only where something can
/// eject — the loader refuses the key anywhere else, and a draw there
/// would shift every such seed's stream for a key that could not act —
/// and on a third of those, across the whole legal range: a threshold
/// only moves where a cluster fails open, so both sides of it have to
/// keep meeting traffic.
fn derivePanicThreshold(random: std.Random, ejects: bool) ?u8 {
    if (!ejects) return null;
    if (random.uintLessThan(u8, 3) != 0) return null;
    const min = zoxy.constants.panic_threshold_percent_min;
    const max = zoxy.constants.panic_threshold_percent_max;
    const threshold = min + random.uintAtMost(u8, max - min);
    assert(threshold >= min);
    assert(threshold <= max);
    return threshold;
}

/// A cluster's #230 passive-ejection draw. A third of adversary seeds
/// opt in, and never a clean one: the signals are a failed dial and an
/// exchange that answered nothing, and a clean seed produces neither —
/// so configuring it there would cost every clean seed a stream shift to
/// exercise a code path that cannot fire.
///
/// `fall` is drawn tight because a scenario is tens of virtual
/// milliseconds long and the adversary refuses at most a fifth of dials:
/// a threshold of five would leave the ejection unreachable on most
/// seeds, which is the axis being unreachable rather than covered — the
/// #258 lesson. `recovery_ms` is drawn short for the same reason, so the
/// re-admission it gates is reachable inside a scenario too.
fn derivePassiveEjection(clean: bool, random: std.Random) ?PassiveEjection {
    if (clean) return null;
    if (random.uintLessThan(u8, 3) != 0) return null;
    const recovery_ms = 1 + random.uintAtMost(u32, 20);
    const draw: PassiveEjection = .{
        .fall = 1 + random.uintAtMost(u8, 2),
        .recovery_ms = recovery_ms,
        // #394's backoff on half of these: a ceiling a few doublings
        // above the base, so repeat ejections inside one scenario walk
        // the levels and an endpoint that recovers long enough resets.
        .recovery_ms_max = if (random.boolean()) recovery_ms * (1 + random.uintAtMost(u32, 7)) else null,
    };
    // The bounds the reachability argument above depends on, stated
    // where they are drawn rather than only in prose.
    assert(draw.fall >= 1 and draw.fall <= 3);
    assert(draw.recovery_ms >= 1);
    assert(draw.recovery_ms < health_interval_floor_ms);
    assert(draw.recovery_ms_max == null or draw.recovery_ms_max.? >= draw.recovery_ms);
    return draw;
}

/// An eighth of adversarial seeds are outage seeds: the HTTP origin
/// stops listening while clients are still live and parked connections
/// still exist — most scenarios wind down within tens of virtual
/// milliseconds, so the outage lands inside that window, paced in
/// milliseconds so fall's three misses do too. Outage seeds check only
/// the http cluster: the tight pacing on a stuck 2 s scenario would
/// otherwise stream hundreds of passing probes into the L4 origin's
/// conn table, while the stopped HTTP origin refuses its probes and a
/// refused probe consumes no origin conn. Everyone else paces from the
/// `health_interval_floor_ms` the origin-capacity bound is derived at.
fn deriveHealthChecks(clean: bool, random: std.Random, timeout_ms: u32, shape: ProbeShape) HealthDraw {
    assert(timeout_ms >= 1);
    const outage = !clean and random.uintLessThan(u8, 8) == 0;
    // Thresholds draw around their defaults so a configured fall/rise —
    // not only the compiled one — decides ejections under the fuzz.
    const tcp_check: Check = .{
        .kind = .tcp,
        .timeout_ms = timeout_ms,
        .fall = 1 + random.uintAtMost(u8, 3),
        .rise = 1 + random.uintAtMost(u8, 2),
    };
    // Half the checked http clusters probe with a real request instead of
    // a dial, so the send and recv legs — and the shutdown that ends one
    // when a deadline or a drain lands mid-leg — take the schedule fuzz.
    // A quarter of those expect a status the origin never sends, which is
    // the only way to reach the wrong-status ejection: every other
    // failure here is a transport failure, and a check that could not
    // tell those apart would be the whole point missed.
    var http_check = tcp_check;
    const fails = random.uintLessThan(u8, 4) == 0;
    // An HTTP/2 cluster (#275) is never probed by HTTP/1.1, which its
    // origin need not speak (`ClusterH2cHttpCheck`): it asks gRPC's health
    // service instead, which fails the same quarter by NOT_SERVING.
    http_check.kind = switch (shape) {
        .http => .{ .http = .{ .path = "/health", .expect_status = if (fails) 599 else 200 } },
        .grpc => .{ .grpc = .{} },
        .dial => .tcp,
    };
    const checked_http = outage or random.boolean();
    var draw: HealthDraw = .{
        // The L4 origin echoes bytes rather than speaking HTTP, so only
        // the dial check is meaningful against it.
        .check_l4 = if (!outage and random.boolean()) tcp_check else null,
        .check_http = checkHttpDraw(checked_http, outage, random, tcp_check, http_check),
        .grpc_health = null,
        .passive_l4 = derivePassiveEjection(clean, random),
        .passive_http = derivePassiveEjection(clean, random),
        .interval_ms = if (outage)
            5 + random.uintAtMost(u32, 10)
        else
            health_interval_floor_ms + random.uintAtMost(u32, 400),
        .http_origin_stop_at_ns = if (outage)
            (10 + random.uintAtMost(u64, 30)) * std.time.ns_per_ms
        else
            0,
    };
    if (draw.check_http) |check| {
        if (check.kind == .grpc) draw.grpc_health = if (fails) zoxy.http.h2.grpc_not_serving else zoxy.http.h2.grpc_serving;
    }
    // An outage always probes the cluster it exists to eject, and the
    // instant always precedes the scenario-end backstop.
    assert(draw.http_origin_stop_at_ns == 0 or draw.check_http != null);
    assert(draw.http_origin_stop_at_ns < scenario_end_ns);
    assert(draw.interval_ms >= 1);
    return draw;
}

/// The deterministic half of the topology: two listeners, and the §7
/// filters on the HTTP one — one action each, scoped to a distinct path
/// so they fire only for the filter_* scripts and leave every other
/// script's golden outcome untouched: reject `/reject`, add a header
/// under `/edit`, rewrite `/rewrite` → `/sim`.
///
/// `forwarded` is the one drawn part: §7 client-address forwarding adds a
/// rendered header on every request the listener serves, so it is a
/// data-path state the sweep has to reach rather than leave to the
/// directed tests. It cannot perturb a golden outcome — the scripts assert
/// on what the *client* receives, and this only changes what the origin
/// sees — and the origin oracle rejects malformed bytes either way.
/// A third of seeds leave §7 forwarding off — the shape every config that
/// predates it keeps — and the rest split between the two trust modes, so
/// the render's suppression and the chain assembly both take the schedule
/// fuzz rather than only the directed tests.
///
/// The mode alone is not coverage, and the census said so. `append` and
/// `replace` render identical bytes unless a request actually carries an
/// inbound chain, so what separates them lives in the scripts:
/// `forwarded_inbound` supplies one every mode must handle, and
/// `forwarded_oversize` one that only `append` can drop.
fn deriveForwarded(random: std.Random) ?zoxy.config.Config.Listener.Forwarded {
    return switch (random.uintLessThan(u8, 3)) {
        0 => null,
        1 => .replace,
        else => .append,
    };
}

/// The #142 receive gate on the l4 listener: a third of seeds require a
/// PROXY header, clean seeds included — the phase is deterministic, so a
/// clean seed's headers always complete and the golden oracles gain the
/// accept path, while adversarial seeds split headers across deliveries
/// and cut them mid-read. Like `deriveForwarded`, the mode alone is not
/// coverage: what the clients *send* decides which verdict fires, and
/// `deriveProxyHeader` scripts that spread — including no header at all,
/// which is the refusal `require` exists to make.
fn deriveProxyProtocol(random: std.Random) ?zoxy.config.Config.Listener.ProxyProtocol {
    if (random.uintLessThan(u8, 3) == 0) {
        return .require;
    }
    return null;
}

/// The #142 send half on the l4 cluster: half the announcing seeds speak
/// v2 (what the writers' real receivers — cloud LBs, HAProxy — expect),
/// the rest v1, and half send nothing at all. Drawn independently of the
/// receive gate, so the sweep reaches all four quadrants — including the
/// chain, where the identity announced in must be the identity announced
/// out. The prober needs no carve-out: `check_l4` is always the
/// dial-only tcp check, which gives a stripping origin no bytes to
/// judge.
fn deriveProxyProtocolSend(random: std.Random) ?zoxy.config.Config.Cluster.ProxyProtocolSend {
    return switch (random.uintLessThan(u8, 6)) {
        0 => .v1,
        1, 2 => .v2,
        else => null,
    };
}

/// How many §4 terminating clients this seed runs (#125), and so whether
/// it binds a terminating listener at all. A quarter of seeds draw one or
/// two: enough that ~1000 sessions cross the sweep — well past the census
/// floor for a rung to fire reliably — while a real handshake's ~260 µs
/// on each side keeps the gate inside the ~5 s it is run at.
///
/// Refused outright when the l4 cluster announces itself with a PROXY
/// header. That header stages into the relay buffer, which is not where a
/// terminated connection's wire bytes come from, and `config.zig` rejects
/// the pair at load — so a harness that hand-built it would be simulating
/// a deployment nobody can configure.
fn deriveTlsClients(
    random: std.Random,
    send: ?zoxy.config.Config.Cluster.ProxyProtocolSend,
    force_exhaustion: bool,
) u8 {
    if (send != null) return 0;
    if (random.uintLessThan(u8, 4) != 0) return 0;
    // A starved seed runs the full population against its single engine,
    // which is the only way `shed_tls_engines` is reached: with one client
    // the pool is never contended, and drawing the count independently
    // left the rung silent across the whole sweep.
    if (force_exhaustion) return tls_clients_max;
    return 1 + random.uintLessThan(u8, tls_clients_max);
}

/// The §4 engine pool this seed runs with. Zero when it drew no
/// terminating clients, which keeps the pool free to every scenario that
/// does not use it.
///
/// A starved seed gets exactly one engine against up to two sessions:
/// the §4 wall, which is what it was drawn to meet, and the only way
/// `shed_tls_engines` is reached. Every other seed is sized so no session
/// is shed — and that means the drawn count *plus one*, not the drawn
/// count. #204's resuming client dials from the end hook of the session
/// whose ticket it offers, and that session's engine is released a loop
/// turn later, when the server sees the close; the two overlap, and
/// sizing to the population would shed the resumption rather than cover
/// it.
fn deriveTlsEngines(tls_clients: u8, force_exhaustion: bool) u32 {
    assert(tls_clients <= tls_clients_max);
    if (tls_clients == 0) return 0;
    if (force_exhaustion) return 1;
    return @as(u32, tls_clients) + 1;
}

/// Whether a seed steps its wall clock past a rotation interval (#202).
/// Half of the seeds that terminate TLS, and none of the rest: a
/// plaintext seed seals no ticket, so a jump there would move nothing
/// while shifting the whole sweep's stream position — the same argument
/// that keeps the terminating listener off a plaintext seed's budgets.
fn deriveClockJump(tls_clients: u8, random: std.Random) bool {
    assert(tls_clients <= tls_clients_max);
    if (tls_clients == 0) return false;
    return random.boolean();
}

/// The #159 bodies every seed's config names: the page for `403` — the
/// one status a script earns from a filter reject — and the `respond`
/// action's answer. Rendered by resolving, as a file's would be, and the
/// client oracle demands them byte for byte on every seed.
const error_body_name = "sim-error";
const respond_body_name = "sim-respond";
const bodies = [_]zoxy.Options.Body{
    .{ .name = error_body_name, .bytes = l7.canon.error_page_body, .content_type = l7.canon.page_content_type },
    .{ .name = respond_body_name, .bytes = l7.canon.respond_body, .content_type = l7.canon.page_content_type },
};
const error_pages = [_]zoxy.Options.ErrorPage{.{ .status = 403, .body = error_body_name }};

/// The #140 names every seed's config logs.
const log_request_headers = [_][]const u8{l7.canon.log_request_header};
const log_response_headers = [_][]const u8{l7.canon.log_response_header};

/// The §7 request rules and the #175 response rules the http listener
/// runs — and, on the seeds whose tls listener terminates http, that one
/// too (#215). Split from `wireListeners` when attaching the second
/// listener's chain took it past the length limit; the two halves are
/// what a listener is made of, in the order the config reads.
fn wireFilters(harness: *Harness) void {
    harness.request_filters_http = request_filters_sim;
    harness.response_filters_http = response_filters_sim;
    assert(harness.request_filters_http.len == request_filters_sim.len);
    assert(harness.response_filters_http.len == response_filters_sim.len);
}

/// The request rules, in the order the walk meets them.
const request_filters_sim = [_]zoxy.Options.Listener.Filter{
    // Decoys first, each the root prefix every request meets and one
    // predicate none does: a predicate that misfired would answer
    // every request 403.
    .{ .match = .{ .path_prefix = "/", .clients = &decoy_client_prefixes }, .actions = &.{.{ .reject = 403 }} },
    .{ .match = .{ .path_prefix = "/", .methods = decoy_methods }, .actions = &.{.{ .reject = 403 }} },
    .{ .match = .{ .path_prefix = "/", .host = decoy_host }, .actions = &.{.{ .reject = 403 }} },
    .{
        .match = .{ .path_prefix = "/", .headers = &.{.{
            .name = l7.canon.log_request_header,
            .predicate = .{ .equals = decoy_value },
        }} },
        .actions = &.{.{ .reject = 403 }},
    },
    .{
        .match = .{ .path_prefix = "/", .headers = &.{.{
            .name = l7.canon.log_request_header,
            .predicate = .{ .contains = decoy_value },
        }} },
        .actions = &.{.{ .reject = 403 }},
    },
    // The rules the scripts aim at carry every predicate kind as well,
    // each one their requests meet: only the HTTP/1.1 scripts reach
    // these prefixes, each a GET naming `script_host`, from a sweep
    // client. A predicate that missed would leave its script without
    // the answer it is owed.
    .{
        .match = .{
            .path_prefix = "/reject",
            .methods = get_only,
            .host = l7.canon.script_host,
            .clients = &sweep_client_prefixes,
        },
        .actions = &.{.{ .reject = 403 }},
    },
    .{
        // #176: composed target, no host override — the Location the
        // client oracle demands is scheme + the request's own host +
        // its canonical path, `l7.canon.redirect_location` exactly.
        .match = .{ .path_prefix = "/redirect" },
        .actions = &.{.{ .redirect = .{ .status = 301, .target = .{ .composed = .{
            .scheme = .https,
        } } } }},
    },
    .{
        // #159: answered from a configured body, before any
        // post-parse resource is acquired and without reaching an
        // origin, so the sweep exercises the static path's
        // body-carrying arm.
        .match = .{ .path_prefix = "/respond", .headers = &.{.{
            .name = "host",
            .predicate = .{ .contains = script_host_fragment },
        }} },
        .actions = &.{.{ .respond = .{ .status = 200, .body = respond_body_name } }},
    },
    .{
        .match = .{ .path_prefix = "/edit", .headers = &.{.{
            .name = "Host",
            .predicate = .{ .equals = l7.canon.script_host },
        }} },
        .actions = &.{.{ .header_set = .{ .name = "X-Sim-Filter", .value = "on" } }},
    },
    .{
        .match = .{ .path_prefix = "/rewrite" },
        .actions = &.{.{ .rewrite_prefix = .{ .from = "/rewrite", .to = "/sim" } }},
    },
    // #331's pair, and the only rules here whose meaning is in their
    // *order*: the allow stops the walk, so the reject beneath it
    // never fires — and a sweep where it did would answer 403 to a
    // script whose golden outcome is the origin's 200. The reject is
    // what makes the allow observable at all; without it the first
    // rule would be indistinguishable from no rule.
    .{
        .match = .{ .path_prefix = "/allow" },
        .actions = &.{.allow},
    },
    .{
        .match = .{ .path_prefix = "/allow" },
        .actions = &.{.{ .reject = 403 }},
    },
};

/// #175 response rules, always on: every response the render forwards
/// gains the stamp — so the client can require it on every 200 and
/// refuse it on every static, which is what separates the two render
/// paths from outside — and the 5xx rule matches a class the scripted
/// origin never answers, so its edit appearing anywhere is the class
/// predicate misfiring under some schedule.
const response_filters_sim = [_]zoxy.Options.Listener.ResponseFilter{
    .{
        .match = .{},
        .actions = &.{.{ .header_set = .{
            .name = l7.canon.response_edit_name,
            .value = l7.canon.response_edit_value,
        } }},
    },
    .{
        .match = .{ .status_class = .@"5xx" },
        .actions = &.{.{ .header_set = .{ .name = l7.canon.response_never_name, .value = "1" } }},
    },
    // The same never-edit behind a status no origin answers, and
    // behind a header value none sends.
    .{
        .match = .{ .statuses = &.{ 207, 299 } },
        .actions = &.{.{ .header_set = .{ .name = l7.canon.response_never_name, .value = "1" } }},
    },
    .{
        .match = .{ .headers = &.{.{ .name = "content-length", .predicate = .{ .equals = decoy_value } }} },
        .actions = &.{.{ .header_set = .{ .name = l7.canon.response_never_name, .value = "1" } }},
    },
};

fn wireListeners(harness: *Harness, forwarded: ?zoxy.config.Config.Listener.Forwarded) void {
    harness.wireFilters();
    harness.listener_options = .{
        .{
            .bind = .{ .ip = bindAddress() },
            .protocol = .{ .l4 = .{
                .target = if (harness.l4_sni)
                    .{ .routes = harness.l4_sni_routes[0..harness.l4_sni_route_count] }
                else
                    .{ .cluster = l4_cluster_name },
                .proxy_protocol = harness.proxy_protocol_l4,
            } },
            .connection_policies = &harness.connection_policy_selections,
        },
        .{
            .bind = .{ .ip = httpBindAddress() },
            .connection_policies = &harness.connection_policy_selections,
            .protocol = .{ .http = .{
                .target = .{ .routes = &harness.routes_http },
                .request_filters = &harness.request_filters_http,
                .request_policies = harness.requestPolicies(),
                .response_policies = &harness.response_policy_selections,
                .response_filters = &harness.response_filters_http,
                .forwarded = forwarded,
                .upgrades = .{ .websocket = harness.upgrades_http },
                .h2c = harness.h2c_http,
                .max_body_bytes = harness.max_body_bytes,
                .keepalive_requests = harness.keepalive_requests,
            } },
        },
        harness.terminatingListener(),
    };
}

/// The §4 terminating listener: bound only on a seed that drew TLS
/// clients, and speaking whichever protocol `deriveTerminatingDraws`
/// chose. Both, across seeds: termination is a phase ahead of the
/// protocol, so the two combinations exercise genuinely different code —
/// the L4 relay's transform hooks against the L7 head-fill source and
/// client-write channel.
fn terminatingListener(harness: *Harness) zoxy.Options.Listener {
    // The harness loads its credentials itself from these same bytes, so
    // what this states is only that the listener terminates — which is
    // what `Server.start` checks its credentials table against.
    const tls: ?zoxy.Options.Listener.Tls = if (harness.tls_clients >= 1) .{
        .cert_pem = zoxy.tls.testdata.cert_pem,
        .key_pem = zoxy.tls.testdata.key_pem,
        .label = "the harness's fixture",
        // #297: stated so the config prices them; the harness loads the
        // set itself, as it loads the default (`loadCertificateSet`).
        .certificates = if (harness.tls_sni) &sni_certificates else &.{},
        .client_ca = if (harness.tls_client_verify) |client_verify|
            .{ .ca_pem = zoxy.tls.testdata.client_ca_pem, .verify = client_verify }
        else
            null,
        // HTTP/1.1 first: zssl picks by the listener's order (RFC 7301
        // §3.2 leaves it to the server), so a slot offering both keeps its
        // HTTP/1.1 script, and only one offering `h2` alone meets HTTP/2.
        .alpn = if (harness.tls_h2) &.{ .http_1_1, .h2 } else null,
    } else null;
    return .{
        .bind = .{ .ip = tlsBindAddress() },
        .tls = tls,
        // Ahead of the handshake: a refusal here would cost none.
        .connection_policies = &harness.connection_policy_selections,
        .protocol = switch (harness.tls_protocol) {
            // The same chain the plaintext http listener runs (#215): the
            // claim termination rests on is that TLS is a phase ahead of
            // the protocol and not a protocol of its own — the same
            // render, the same filters, the same stamps. Its own routes,
            // so a terminated connection's origin conn is one
            // `verifyUpstreamIdentities` can tell from a plaintext one's.
            .http => .{
                .http = .{
                    .target = .{ .routes = &harness.routes_tls },
                    .request_filters = &harness.request_filters_http,
                    .request_policies = harness.requestPolicies(),
                    .response_policies = &harness.response_policy_selections,
                    .response_filters = &harness.response_filters_http,
                    // No #236 body cap, stated rather than inherited: the cap
                    // is a *plaintext-leg* draw, and a terminated run of a
                    // body-carrying script is judged by `terminating_pair`'s
                    // spec, whose legal set omits `413`.
                    .max_body_bytes = 0,
                    .keepalive_requests = zoxy.defaults.keepalive_requests,
                    // #449: HTTP/3 on the same port, over UDP.
                    .quic = if (harness.quic_http) .{ .bind = .{ .ip = tlsBindAddress() } } else null,
                },
            },
            // An l4 terminator relays to the l4 cluster, which the http
            // chain's filters and policies have no head to apply to.
            .l4 => .{ .l4 = .{ .target = .{ .cluster = l4_cluster_name } } },
        },
    };
}

/// The staging size this seed runs with (§8, §9). Adversarial seeds sit
/// at the floor — one worst-case line, which holds about eighteen of the
/// sweep's real ones — so the buffer swap runs constantly and lines meet
/// a nearly-full buffer, against the default's headroom (about eighty
/// real lines) where the swap fires once a scenario. The *drop* rung
/// itself is meant to stay out of reach: it needs a scenario's lines to
/// outrun the floor inside one slow sink write, so it is pinned by a
/// directed test (`access_log_test.zig`) rather than left to the sweep.
///
/// The one scenario that does generate it is Rapid Reset (#276): a
/// hundred lines, as fast as PONGs return, outrun any smaller staging
/// behind the adversary's slow sink. A seed that may draw it stages at
/// the ceiling, which holds them all, so the drop rung stays the
/// directed test's.
///
/// A seed with HTTP/3 clients (#449) stages at the default too, on
/// evidence rather than arithmetic. Its clients add at most
/// `h3_clients_max * H3Client.streams_max` (eight) lines, and soak #144
/// found two seeds (558591242, 559342788) whose lines — HTTP/2 sheds,
/// HTTP/3 answers, aborts — all landed inside one slow sink write and
/// outran the floor. Those seeds give up the floor's swap pressure; the
/// rest keep it. A population without HTTP/3 can in principle outrun the
/// floor as well — six HTTP/2 clients at four streams each — but no soak
/// has seen it in hundreds of millions of seeds, and the census entry is
/// the alarm if one does. Bounding the staging by the drawn population
/// would be exact, but the population is drawn after the server starts.
///
/// The floor is one line of *this* config, not the static minimum:
/// #140's named headers widen a line, so the floor is computed from this
/// config's own header lists, or the drop rung would fire on arithmetic
/// rather than on the backpressure it is there to force.
fn deriveAccessLogBuffer(harness: *const Harness) u32 {
    if (harness.config.access_log_sink == null) {
        return 0;
    }
    if (harness.h2_rapid_reset) return zoxy.constants.access_log_buffer_bytes_max;
    if (harness.clean or harness.h3_count != 0) {
        return zoxy.constants.access_log_buffer_bytes_default;
    }
    const floor = @max(
        zoxy.constants.access_log_buffer_bytes_min,
        zoxy.constants.accessLogLineBytes(
            log_request_headers.len + log_response_headers.len,
        ),
    );
    assert(floor >= zoxy.constants.access_log_buffer_bytes_min);
    assert(floor <= zoxy.constants.access_log_buffer_bytes_max);
    return floor;
}

/// The pool sizes this seed runs the server with. A quarter of
/// adversarial seeds shrink them to force the §8 rungs; clean seeds keep
/// ample pools so golden outcomes never meet a shed. Decided in `setUp`
/// (see `force_exhaustion`) because the ring size had to precede
/// `io.init`.
/// The pool sizes the server runs with. Authoritative here, not the
/// resolved `config.limits`: a starved seed sizes pools past what options
/// may state (`limitsStated`).
fn deriveInitOptions(harness: *const Harness, random: std.Random) ServerSim.InitOptions {
    var options = harness.derivePoolOptions(random);
    // #275: the HTTP/2 origin pools, which only an HTTP/2 cluster has. The
    // limits here are built rather than resolved, so they would be the
    // type's zeros; the connections are what the loader derived, and the
    // streams every upstream slot, as the loader's own default is.
    if (harness.http_protocol != .http1) {
        options.h2_origin_connections = harness.config.limits.h2_origin_connections;
        options.h2_origin_streams = options.upstream_slots;
        assert(options.h2_origin_connections >= 1);
    }
    // #296: an HTTPS cluster's TLS sessions, one per upstream slot — what
    // the loader allows when asked, and wider than its per-endpoint default
    // on a clean seed, whose exchanges a session pool may not shed.
    if (harness.http_tls) {
        options.upstream_tls_sessions = options.upstream_slots;
        assert(options.upstream_tls_sessions <= zoxy.constants.upstream_tls_sessions_max);
    }
    assert(options.h2_origin_streams <= options.upstream_slots);
    return options;
}

fn derivePoolOptions(harness: *const Harness, random: std.Random) ServerSim.InitOptions {
    const force_exhaustion = harness.force_exhaustion;
    const access_log_buffer_bytes = harness.deriveAccessLogBuffer();
    return if (force_exhaustion)
        .{
            // head_buffers ≤ conn_slots is a Server.init precondition, so
            // the slot draw starts at whatever the ring draw chose.
            .conn_slots = harness.head_buffers + random.uintLessThan(u32, 2),
            .relay_buffers = 1,
            .upstream_slots = 1,
            // #437: no more than the one upstream slot every consult holds,
            // which is also what lets a consult meet that slot's wall — and
            // a second consult the one consult slot's.
            .consult_slots = 1,
            .head_buffers = harness.head_buffers,
            // Clamped, because a starved seed's slot count is drawn from
            // the ring and can sit below the pool the upgrade draw asked
            // for — and a tunnel is an accepted connection, so a pool
            // wider than the slots that hold one cannot exist (§5). A
            // clamp to zero is legal here and means every handshake on
            // this seed meets the tunnel rung, which is coverage rather
            // than a loss.
            .tunnels = @min(harness.tunnels, harness.head_buffers),
            // Clamped like the tunnels, and for the same reason: a session
            // is a connection's, and a starved seed's slots may be fewer.
            .h2_connections = @min(harness.h2_connections, harness.head_buffers),
            .stream_slots = if (@min(harness.h2_connections, harness.head_buffers) == 0 and !harness.quic_http)
                0
            else
                harness.stream_slots,
            // A QUIC connection holds a conn slot, so the pool fits the
            // starved slots — and is never empty on a seed that binds one.
            .quic_connections = @min(harness.quic_connections, harness.head_buffers),
            // Capacity 1: the first render engages the pressure flag, so
            // the engage counter stays reachable even though the shed
            // rung itself is relay-shadowed (see sim/main.zig uncovered).
            .upstream_head_buffers = 1,
            .relay_buffer_bytes = harness.relay_buffer_bytes,
            .access_log_buffer_bytes = access_log_buffer_bytes,
            // One engine, which the QUIC connections share with the TCP
            // ones: what reaches `h3_shed_tls_engines` (#449).
            .tls_engines = deriveTlsEngines(harness.tls_clients, force_exhaustion),
        }
    else
        .{
            .relay_buffer_bytes = harness.relay_buffer_bytes,
            .tunnels = harness.tunnels,
            .h2_connections = harness.h2_connections,
            .stream_slots = harness.stream_slots,
            .quic_connections = harness.quic_connections,
            .access_log_buffer_bytes = access_log_buffer_bytes,
            // Clean seeds size every pool at `clean_pool_capacity`
            // (watermark 41 of 54, over at most 27 exchanges); the
            // comptime block at the top proves the margin, so a
            // population bump fails there. The upstream margin also
            // rides the single-endpoint topology (checkout-before-
            // dial caps acquired at the live client count — parked
            // conns per endpoint could accumulate past it under a
            // multi-endpoint clean topology). Adversarial seeds keep
            // the tighter pools: meeting pressure is their coverage.
            .conn_slots = if (harness.clean) clean_pool_capacity else 2 * clients_max,
            .relay_buffers = if (harness.clean) clean_pool_capacity else clients_max,
            .upstream_slots = if (harness.clean) clean_pool_capacity else 2 * clients_max,
            // #437: every exchange's consult on a clean seed, since an
            // HTTP/2 client's streams consult side by side.
            .consult_slots = if (harness.clean) exchanges_max else adversarial_consult_slots,
            .head_buffers = harness.head_buffers,
            .upstream_head_buffers = if (harness.clean)
                clean_pool_capacity
            else
                2 * clients_max,
            // Every QUIC connection holds an engine for its life (#449).
            .tls_engines = deriveTlsEngines(harness.tls_clients, force_exhaustion) + harness.quic_connections,
        };
}

/// A third of seeds bind the admin listener (§8) and scrape it once or
/// twice. On an adversarial seed a scraper may hold its half open after
/// the plane's FIN, so the plane is still draining it when the scenario's
/// drain tears it down; a clean seed's read to the end and close.
fn drawAdmin(harness: *Harness, arena: std.mem.Allocator, seed: u64) !void {
    var admin_prng = std.Random.DefaultPrng.init(seed ^ 0x0008_0008_0008_0008);
    const random = admin_prng.random();
    harness.admin_scrapers = &.{};
    if (random.uintLessThan(u8, 3) != 0) return;
    const count = 1 + random.uintLessThan(u8, admin_scrapers_max);
    assert(count >= 1);
    assert(count <= admin_scrapers_max);
    harness.admin_scrapers = try arena.alloc(AdminScraper, count);
    for (harness.admin_scrapers) |*scraper| {
        scraper.* = .{};
        const hold = !harness.clean and random.boolean();
        scraper.prepare(&harness.io, admin_address, hold, harness.clean);
        scraper.on_ended = clientEndedHook;
        scraper.context = harness;
    }
    assert(harness.admin_scrapers.len <= admin_scrapers_max);
}

/// The admin listener's bind, apart from every data-path address.
const admin_address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9100 } };

/// #275's and #296's draw: a quarter of seeds' http cluster speaks HTTP/2
/// to its origins — in the clear by prior knowledge on half of those, over
/// TLS (ALPN `h2`) to the origin fixture on the rest — and `h2_origin`
/// answers in `origin_http`'s place; an eighth speak HTTP/1.1 over TLS to
/// `https_origin`. Each answers with the canonical sized 200 every client
/// already judges.
fn drawHttpProtocol(harness: *Harness, seed: u64) void {
    harness.grpc_prng = std.Random.DefaultPrng.init(seed ^ 0x0004_0004_0004_0004);
    harness.tls_h2_prng = std.Random.DefaultPrng.init(seed ^ 0x0271_0002_0271_0002);
    harness.h2_tuning_prng = std.Random.DefaultPrng.init(seed ^ 0x0009_0113_0009_0113);
    harness.h2_violation_prng = std.Random.DefaultPrng.init(seed ^ 0x9113_0005_9113_0005);
    harness.h2_handler_prng = std.Random.DefaultPrng.init(seed ^ 0x0434_0002_0434_0002);
    harness.h2_shape_prng = std.Random.DefaultPrng.init(seed ^ 0x9113_0008_9113_0008);
    harness.h2_shapes_answered = @splat(0);
    var protocol_prng = std.Random.DefaultPrng.init(seed ^ 0x0275_0275_0275_0275);
    const random = protocol_prng.random();
    const roll = random.uintLessThan(u8, 8);
    harness.http_protocol = switch (roll) {
        0 => .h2c,
        1 => .h2,
        else => .http1,
    };
    // #296: an eighth of seeds put the HTTP/1.1 origin behind TLS.
    harness.http_tls = roll == 2;
    assert(!harness.http_tls or harness.http_protocol == .http1);
    // HTTP/2 or not, the cluster's origin answers at one address: the one
    // the #178 sticky tag is minted from.
    assert(harness.http_protocol.http2() == (harness.http_protocol != .http1));
}

/// The canonical sized 200 in HTTP/2's terms: the length stated, so the
/// proxy frames it for HTTP/1.1 clients as the HTTP/1.1 origin does, and
/// the logged header the access-log oracle reads.
const h2_origin_headers = [_]zoxy.http.h2.Pair{
    .{ "content-length", "32" },
    .{ l7.canon.log_response_header, l7.canon.log_response_value },
};

/// The shapes the HTTP/2 origin answers in: the HTTP/1.1 origin's
/// well-formed ones (`l7.OriginMode`), in HTTP/2's terms, so every client
/// judges them by the same octets. With no length, the proxy frames the
/// answer chunked for HTTP/1.1 (`h2/origin.zig`), one chunk per DATA
/// frame, and the origin sends one. A trailer section closes the chunked
/// stream for HTTP/1.1, and goes on as trailing HEADERS for HTTP/2 and
/// HTTP/3. An interim `100` comes ahead of the sized answer (#232).
pub const H2OriginShape = enum(u8) { sized, chunked, chunked_trailers, interim_then_sized };
const h2_origin_shapes = [_]zoxy.http.h2.Answer{
    .{ .status = "200", .headers = &h2_origin_headers, .body = l7.canon.sized_body },
    .{ .status = "200", .body = l7.h2_canonical_chunked_body },
    .{
        .status = "200",
        .headers = &.{
            .{ "trailer", l7.canon.response_trailer_name },
            .{ l7.canon.response_trailer_owed_header, "1" },
        },
        .body = l7.h2_canonical_chunked_body,
        .trailers = &.{.{ l7.canon.response_trailer_name, l7.canon.response_trailer_value }},
    },
    .{ .status = "200", .headers = &h2_origin_headers, .body = l7.canon.sized_body, .interim = "100" },
};

comptime {
    assert(h2_origin_shapes.len == std.enums.values(H2OriginShape).len);
    assert(h2_origin_shapes[@backingInt(H2OriginShape.chunked_trailers)].trailers.len == 1);
}

/// Each request's shape: behind an interim on an interim seed, as the
/// HTTP/1.1 origin answers there (`pickHttpOriginMode`), and drawn
/// otherwise — on clean seeds too. Every shape is well-formed, and only
/// a clean seed's golden oracle demands the whole answer: off one, a
/// chunk the proxy framed wrong is refused by its own scanner, and the
/// cut that leaves passes as the adversary's.
fn pickH2Answer(context: *anyopaque) ?*const zoxy.http.h2.Answer {
    const harness: *Harness = @ptrCast(@alignCast(context));
    const shape: H2OriginShape = if (harness.interim_http)
        .interim_then_sized
    else
        harness.h2_shape_prng.random().enumValue(H2OriginShape);
    assert(!harness.interim_http or shape == .interim_then_sized);
    assert(@backingInt(shape) < h2_origin_shapes.len);
    return &h2_origin_shapes[@backingInt(shape)];
}

fn countH2Answer(context: *anyopaque, answer: *const zoxy.http.h2.Answer) void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    var matched: u32 = 0;
    for (&h2_origin_shapes, &harness.h2_shapes_answered) |*shape, *count| {
        if (shape != answer) continue;
        count.* += 1;
        matched += 1;
    }
    assert(matched == 1);
}

/// The http listeners' request policies: the listener's own, then the
/// #437 consult — except where the http cluster speaks HTTP/2 (#275) or
/// TLS (#296), which no consult may ask (`extension.consultable`), so its
/// `consult_get` routes as a plain GET there.
fn requestPolicies(harness: *const Harness) []const zoxy.extension.Selection {
    assert(harness.policy_selections.len == 2);
    const count: usize = if (harness.http_protocol == .http1 and !harness.http_tls) 2 else 1;
    return harness.policy_selections[0..count];
}

/// The two scripted nameservers' addresses (#481), on no other port.
const nameserver_addresses = [_]std.Io.net.IpAddress{
    .{ .ip4 = .{ .bytes = .{ 10, 53, 0, 1 }, .port = 53 } },
    .{ .ip4 = .{ .bytes = .{ 10, 53, 0, 2 }, .port = 53 } },
};

/// The name a #481 seed's L4 cluster follows.
const dns_origin_name = "origin.sim.test";

/// #481's draw: a quarter of seeds have the L4 cluster follow a name. A
/// clean seed's nameservers answer the origin alone, so the set never
/// moves under its golden outcomes. An adversarial seed's each draw a
/// behaviour and answer, from the first round on, the origin and two
/// refusing addresses — past `addresses_max`, so the answer is cut to the
/// first two and the set still moves — and from 150 ms on, nothing at all,
/// a set no cluster can take. The first round is the one most scenarios
/// see, since few outlast the refresh floor. Its own stream.
fn drawDns(harness: *Harness, seed: u64) void {
    var dns_prng = std.Random.DefaultPrng.init(seed ^ 0x0481_0481_0481_0481);
    const random = dns_prng.random();
    harness.dns_l4 = random.uintLessThan(u8, 4) == 0;
    harness.dns_behaviors = .{ .answer, .answer };
    if (!harness.clean) {
        for (&harness.dns_behaviors) |*behavior| behavior.* = random.enumValue(zoxy.testing.Behavior);
    }
    // A clean seed's second phase is the first again, at the scenario's
    // end: there only so both draws fill the same two-phase array.
    harness.dns_phases = if (harness.clean) .{
        .{ .from_ns = 0, .addresses = &dns_origin_only },
        .{ .from_ns = scenario_end_ns, .addresses = &dns_origin_only },
    } else .{
        .{ .from_ns = 0, .addresses = &dns_origin_moved },
        .{ .from_ns = 150 * std.time.ns_per_ms, .addresses = &.{} },
    };
    harness.dns_zone = .{
        .phases = &harness.dns_phases,
        .behaviors = &harness.dns_behaviors,
        .start_ns = 0,
        .ttl_s = random.uintAtMost(u32, 1),
    };
    // What `App` would have resolved before step zero: the sim builds the
    // server itself, so it states the name's first answer.
    harness.dns_names = .{.{ .host = dns_origin_name, .port = originAddress().getPort(), .addresses = &dns_origin_only }};
    assert(harness.dns_phases[0].from_ns == 0);
}

const dns_origin_only = [_]std.Io.net.IpAddress{.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } }};
/// The origin and two hosts nobody listens on, in address order: one past
/// the cluster's `addresses_max`, so the last is the one cut. Distinct
/// hosts, since a record carries an address alone — the port is the
/// name's own.
const dns_origin_moved = [_]std.Io.net.IpAddress{
    .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } },
    .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9000 } },
    .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 9000 } },
};

fn startNameservers(harness: *Harness) !void {
    assert(harness.dns_l4);
    harness.dns_zone.start_ns = harness.io.nowNs();
    for (&harness.nameservers, 0..) |*nameserver, index| {
        try nameserver.start(&harness.io, &harness.dns_zone, @intCast(index), nameserver_addresses[index]);
    }
    assert(harness.dns_zone.queries_seen == 0);
}

/// #298's draw: a third of seeds have the L4 listener choose its route by
/// the ClientHello's name — one named route, and on half of those an
/// any-name route too — and each of their L4 clients that speaks sends a
/// hello naming the route, another name, nothing, or bytes that are no
/// hello at all. Its own stream, here and per client.
fn drawL4Sni(harness: *Harness, seed: u64) void {
    harness.l4_sni_prng = std.Random.DefaultPrng.init(seed ^ 0x0298_0298_0298_0298);
    const random = harness.l4_sni_prng.random();
    harness.l4_sni = random.uintLessThan(u8, 3) == 0;
    harness.l4_hello_kinds = @splat(null);
    harness.l4_sni_routes[0] = .{ .sni = sni_route_name, .cluster = l4_cluster_name };
    harness.l4_sni_routes[1] = .{ .sni = null, .cluster = l4_cluster_name };
    harness.l4_sni_route_count = if (random.boolean()) 2 else 1;
    assert(harness.l4_sni_route_count >= 1);
}

/// The name the #298 table routes, and one it does not.
const sni_route_name = "route.zoxy.test";
const sni_other_name = "elsewhere.zoxy.test";

/// What one of a #298 seed's L4 clients opens with.
const HelloKind = enum(u8) { named, other, absent, garbage };

/// The token a #298 seed's speaking L4 client sends in place of random
/// bytes, written into `token`, and its length; null where the seed routes
/// no name or the client is silent.
fn drawHello(harness: *Harness, l4_index: u8, silent: bool, token: *[l4.token_bytes_max]u8) ?u8 {
    assert(l4_index < clients_max);
    if (!harness.l4_sni or silent) return null;
    const random = harness.l4_sni_prng.random();
    const kind = random.enumValue(HelloKind);
    harness.l4_hello_kinds[l4_index] = kind;
    const salt = l4_index + 1;
    const hello = switch (kind) {
        .named => l4.clientHello(token, sni_route_name, salt),
        .other => l4.clientHello(token, sni_other_name, salt),
        .absent => l4.clientHello(token, null, salt),
        .garbage => garbage: {
            // Not a TLS record: a handshake record begins 0x16.
            @memset(token[0..24], salt);
            token[0] = 0x00;
            break :garbage token[0..24];
        },
    };
    assert(hello.len >= 1);
    return @intCast(hello.len);
}

/// What the peek must have counted (#298), from what each client opened
/// with: never more than that on any seed, and exactly that on a clean
/// seed whose listener reads no PROXY header, which could close a client
/// first. But one: a client that hangs up before its hello is whole —
/// silent, or cut mid-hello by the adversary — is counted invalid, the
/// verdict bytes that are no hello get, so on any seed an invalid count
/// may take every client no other verdict did.
fn verifySniCounters(harness: *const Harness) !void {
    const counters = &harness.server.counters;
    const names = [_][]const u8{ "l4_sni_routed", "l4_sni_absent", "l4_sni_no_route", "l4_sni_invalid" };
    const invalid_index = 3;
    comptime assert(std.mem.eql(u8, names[invalid_index], "l4_sni_invalid"));
    if (!harness.l4_sni) {
        // No listener routes by name on this seed, so no verdict is taken.
        inline for (names) |name| assert(counters.get(name) == 0);
        return;
    }
    const catch_all = harness.l4_sni_route_count == 2;
    // What is owed, in `names`' order: routed, absent, unrouted, invalid.
    var owed: [4]u64 = @splat(0);
    for (harness.l4_hello_kinds[0..harness.l4_count]) |hello_kind| {
        const kind = hello_kind orelse continue;
        switch (kind) {
            .named => owed[0] += 1,
            .other => if (catch_all) {
                owed[0] += 1;
            } else {
                owed[2] += 1;
            },
            .absent => owed[1] += 1,
            .garbage => owed[3] += 1,
        }
    }
    const exact = harness.clean and harness.proxy_protocol_l4 == null;
    var verdicts: u64 = 0;
    inline for (names, owed, 0..) |name, expected, index| {
        const counted = counters.get(name);
        verdicts += counted;
        // Invalid is bounded below, by every client at once.
        if (index != invalid_index and counted > expected) return error.L4SniMiscounted;
        if (exact and counted != expected) return error.L4SniMiscounted;
    }
    if (verdicts > harness.l4_count) return error.L4SniMiscounted;
    // One verdict a client at most; and a table with an any-name route
    // leaves no name unrouted.
    assert(owed[0] + owed[1] + owed[2] + owed[3] <= harness.l4_count);
    if (catch_all) assert(owed[2] == 0);
}

/// The names a TLS slot may ask for (#297): nothing; the default's, which
/// an RSA leaf covers too; each further certificate's exact name, one of
/// them in another case; a name under the wildcard, in either case; the
/// wildcard's apex and a name two labels under it, which it does not
/// cover (RFC 9525 §6.3); and one nothing covers.
const sni_names = [_][]const u8{
    "",
    zoxy.tls.testdata.host_name,
    zoxy.tls.testdata.p384_host_name,
    zoxy.tls.testdata.origin_host_name,
    zoxy.tls.testdata.rsa_host_name,
    "RSA.Zoxy.Test",
    "api." ++ zoxy.tls.testdata.wild_domain,
    "Api.WILD.zoxy.test",
    zoxy.tls.testdata.wild_domain,
    "a.b." ++ zoxy.tls.testdata.wild_domain,
    "other.zoxy.test",
};

/// The further certificates a #297 seed's terminating listener holds,
/// after the default (index 0, P-256 for `host_name`): P-384, a second
/// P-256, RSA for `rsa_host_name` and `host_name`, and a P-256 and an RSA
/// leaf for `*.wild.zoxy.test`. Every leaf has a key of its own.
const sni_certificates = [_]zoxy.Options.Listener.Certificate{
    .{ .cert_pem = zoxy.tls.testdata.p384_cert_pem, .key_pem = zoxy.tls.testdata.p384_key_pem, .label = "the P-384 fixture" },
    .{ .cert_pem = zoxy.tls.testdata.origin_cert_pem, .key_pem = zoxy.tls.testdata.origin_key_pem, .label = "the second P-256 fixture" },
    .{ .cert_pem = zoxy.tls.testdata.rsa_cert_pem, .key_pem = zoxy.tls.testdata.rsa_key_pem, .label = "the RSA fixture" },
    .{ .cert_pem = zoxy.tls.testdata.wild_cert_pem, .key_pem = zoxy.tls.testdata.wild_key_pem, .label = "the P-256 wildcard" },
    .{ .cert_pem = zoxy.tls.testdata.rsa_wild_cert_pem, .key_pem = zoxy.tls.testdata.rsa_wild_key_pem, .label = "the RSA wildcard" },
};

/// Which of `sni_certificates` carry an RSA key: those load without RFC
/// 6979 nonces, which zssl refuses an RSA key (#411). A seed still
/// replays: the trace folds in lengths, never octets, and a PSS
/// signature is its modulus's length whatever salt it drew — where an
/// ECDSA one's DER length moves with its nonce, which is why those sign
/// deterministically.
const sni_certificate_rsa = [_]bool{ false, false, true, false, true };

/// The default and `sni_certificates`: what a #297 listener chooses among.
pub const sni_choices_count = sni_certificates.len + 1;

comptime {
    assert(sni_certificate_rsa.len == sni_certificates.len);
    assert(sni_choices_count <= zoxy.constants.tls_certificates_max);
}

/// Half of seeds give the terminating listener `sni_certificates`, and
/// then each slot draws a name from `sni_names`; the rest name the default
/// alone, as every seed did before. A stream of its own.
/// What a TLS slot answers a #304 CertificateRequest with.
const ClientPresents = enum(u8) {
    /// Nothing: an unauthenticated session where the CA is optional, a
    /// `certificate_required` refusal where it is required.
    none,
    /// The leaf the client CA signed: verified, so its fingerprint goes
    /// on to the origin and the log.
    issued,
    /// A leaf another CA signed (the origin fixture): refused either way,
    /// since a certificate that is presented must verify.
    foreign,
};

/// Half of seeds ask no client for a certificate; the rest split between
/// an optional and a required client CA, and each slot then draws what it
/// presents. Both identities sign deterministically, so a seed replays.
/// A stream of its own.
fn drawClientCa(harness: *Harness, arena: std.mem.Allocator, seed: u64) !void {
    var client_ca_prng = std.Random.DefaultPrng.init(seed ^ 0x0304_0304_0304_0304);
    const random = client_ca_prng.random();
    harness.tls_client_identities = .{ null, null };
    harness.tls_client_presents = @splat(.none);
    harness.tls_client_refusals = 0;
    harness.tls_client_verify = switch (random.uintLessThan(u8, 4)) {
        0 => .optional,
        1 => .required,
        else => null,
    };
    if (harness.tls_client_verify == null) return;
    // No slot of a client-CA seed is shown an RSA leaf
    // (`rsaSaltContained`): one that would be offers ECDSA instead.
    for (&harness.tls_scheme_offers, 0..) |*offer, index| {
        if (harness.slotShownRsa(index)) offer.* = .ecdsa;
        assert(!harness.slotShownRsa(index));
    }
    for (&harness.tls_client_presents) |*presents| presents.* = random.enumValue(ClientPresents);
    const testdata = zoxy.tls.testdata;
    const deterministic: zoxy.tls.Credentials.Options = .{ .deterministic_nonce = true };
    harness.tls_client_identities[0] =
        try zoxy.tls.Credentials.load(arena, testdata.client_cert_pem, testdata.client_key_pem, deterministic);
    harness.tls_client_identities[1] =
        try zoxy.tls.Credentials.load(arena, testdata.origin_cert_pem, testdata.origin_key_pem, deterministic);
    assert(harness.tls_client_identities[0] != null);
}

/// The identity slot `index` presents, as the test client takes one.
fn clientIdentity(harness: *Harness, index: u8) ?*const zoxy.tls.ClientIdentity {
    assert(index < tls_client_slots);
    const slot: usize = switch (harness.tls_client_presents[index]) {
        .none => return null,
        .issued => 0,
        .foreign => 1,
    };
    assert(harness.tls_client_verify != null);
    return &harness.tls_client_identities[slot].?.inner;
}

/// #304: whether slot `index` must be turned away by its listener's client
/// CA — no certificate where one is required, or one that cannot verify.
fn clientRefusalOwed(harness: *const Harness, index: usize) bool {
    const client_verify = harness.tls_client_verify orelse return false;
    return switch (harness.tls_client_presents[index]) {
        .none => client_verify == .required,
        .issued => false,
        .foreign => true,
    };
}

/// A slot its client CA turns away hears nothing back but the refusal —
/// which a clean seed must have delivered — and one it admits is never
/// refused. True when the slot was a refusal, and so is accounted for.
fn verifyClientCertificate(harness: *Harness, client: *const TlsClient, index: usize, back: []const u8) !bool {
    assert(index < tls_client_slots);
    // A listener that asks for a certificate resumes nothing: a ticket
    // seals the PSK alone, and a resumed handshake asks for no certificate
    // (RFC 8446 §4.3.2), so a resumed session would carry no identity to
    // the origin. A session completed and shown no certificate resumed.
    if (harness.tls_client_verify != null and client.handshake_done and client.serverPublicKey() == null) {
        return error.TlsResumedPastClientCa;
    }
    if (!harness.clientRefusalOwed(index)) {
        if (client.refusedForClientCertificate()) return error.TlsClientRefusedWrongly;
        return false;
    }
    if (back.len != 0) return error.TlsClientRefusalServed;
    // A missing certificate is told with `certificate_required`; a chain
    // that fails is a bare teardown (§4), whose witness is the counter.
    const told = harness.tls_client_presents[index] == .none;
    if (harness.clean and told and !client.refusedForClientCertificate()) return error.TlsClientRefusalMissing;
    harness.tls_client_refusals += 1;
    return true;
}

fn drawSni(harness: *Harness, seed: u64) void {
    var sni_prng = std.Random.DefaultPrng.init(seed ^ 0x0297_0297_0297_0297);
    const random = sni_prng.random();
    harness.tls_sni = random.boolean();
    harness.tls_sni_credentials = @splat(null);
    harness.tls_choices_shown = @splat(0);
    harness.tls_scheme_refusals = 0;
    harness.tls_certificate_sets = .{ &.{}, &.{}, &.{} };
    for (&harness.tls_names, &harness.tls_scheme_offers) |*name, *offer| {
        name.* = if (harness.tls_sni) sni_names[random.uintLessThan(u8, sni_names.len)] else zoxy.tls.testdata.host_name;
        // #411: half of a #297 seed's slots narrow their offer — to ECDSA,
        // to P-256 alone, or to RSA-PSS alone — and the rest offer all.
        offer.* = if (!harness.tls_sni) .all else switch (random.uintLessThan(u8, 8)) {
            0 => .ecdsa,
            1 => .p256,
            2, 3 => .rsa,
            else => .all,
        };
    }
    // QUIC's hello always names a host (`QuicClient`): a #297 seed's
    // HTTP/3 clients draw a name past the empty one, and the rest name
    // what the HTTP/3 tests do, which nothing covers.
    for (&harness.h3_names) |*name| {
        name.* = if (harness.tls_sni) sni_names[1 + random.uintLessThan(u8, sni_names.len - 1)] else "localhost";
        assert(name.len >= 1);
    }
    if (!harness.tls_sni) assert(std.mem.eql(u8, harness.tls_names[0], zoxy.tls.testdata.host_name));
}

/// The terminating listener's choices, as `App` builds them: the default
/// first, then each further certificate with the names its leaf covers.
fn loadCertificateSet(harness: *Harness, arena: std.mem.Allocator) !void {
    assert(harness.tls_sni);
    const default = &harness.tls_credentials[2].?;
    harness.tls_certificate_choices[0] = .{
        .credentials = default,
        .names = try zoxy.tls.trust.dnsNames(arena, default.chain[0]),
        .schemes = default.schemes(),
    };
    for (sni_certificates, sni_certificate_rsa, &harness.tls_sni_credentials, harness.tls_certificate_choices[1..]) |certificate, rsa, *slot, *choice| {
        // An ECDSA key signs deterministically, as the default's does, and
        // an RSA key cannot (`sni_certificate_rsa`).
        slot.* = try zoxy.tls.Credentials.load(arena, certificate.cert_pem, certificate.key_pem, .{ .deterministic_nonce = !rsa });
        const credentials = &slot.*.?;
        choice.* = .{
            .credentials = credentials,
            .names = try zoxy.tls.trust.dnsNames(arena, credentials.chain[0]),
            .schemes = credentials.schemes(),
        };
        assert(choice.names.len >= 1);
    }
    harness.tls_certificate_sets[2] = &harness.tls_certificate_choices;
    harness.server.setTlsCertificateSets(harness.tls_certificate_sets[0..harness.listeners_count]);
}

/// Which of the listener's certificates a hello must be shown (#297,
/// #411), or null for one it must be refused. Written out per name from
/// `certificate_set.select`'s contract rather than computed by the same
/// walk: an exact name (any case) before a one-label wildcard before the
/// default; within a tier only a key the offer can verify, and ECDSA
/// before RSA; and a refusal when no tier holds a usable key.
fn expectedChoice(sni: bool, name: []const u8, offer: zoxy.tls.SchemeOffer) ?usize {
    // A listener of one certificate chooses nothing, and only a #297 seed
    // narrows an offer.
    if (!sni) {
        assert(offer == .all);
        return 0;
    }
    const testdata = zoxy.tls.testdata;
    // By offer, in `SchemeOffer`'s order: all, ecdsa, p256, rsa.
    const row: [4]?usize = if (std.ascii.eqlIgnoreCase(name, testdata.host_name))
        // The default and the RSA leaf both name it.
        .{ 0, 0, 0, 3 }
    else if (std.ascii.eqlIgnoreCase(name, testdata.p384_host_name))
        // P-256 alone passes the P-384 leaf over for the default.
        .{ 1, 1, 0, null }
    else if (std.ascii.eqlIgnoreCase(name, testdata.origin_host_name))
        .{ 2, 2, 2, null }
    else if (std.ascii.eqlIgnoreCase(name, testdata.rsa_host_name))
        // An offer without RSA-PSS passes it over for the default.
        .{ 3, 0, 0, 3 }
    else if (std.ascii.eqlIgnoreCase(name, "api." ++ testdata.wild_domain))
        .{ 4, 4, 4, 5 }
    else
        // Nothing, the apex, two labels deep, a name nobody holds.
        .{ 0, 0, 0, null };
    comptime assert(@backingInt(zoxy.tls.SchemeOffer.rsa) == 3);
    return row[@backingInt(offer)];
}

/// Whether slot `index` offers nothing the certificates its name reaches
/// can sign under (#411), and so is refused unless it resumes.
fn schemeRefusable(harness: *const Harness, index: usize) bool {
    assert(index < tls_client_slots);
    const offer = harness.tls_scheme_offers[index];
    return expectedChoice(harness.tls_sni, harness.tls_names[index], offer) == null;
}

/// Whether slot `index`'s full handshake is signed by an RSA leaf.
///
/// `rsaSaltContained`: the salt PSS draws is the one randomness a seed
/// does not choose, and nothing that reaches the trace may depend on it.
/// The signature itself never does — the trace folds in lengths, and a
/// PSS signature is its modulus's length — but it enters the transcript,
/// and so whatever signs or seals over that transcript afterwards. Two
/// things here do, and both are kept off RSA sessions: a client's own
/// CertificateVerify (#304), an ECDSA signature whose DER length moves
/// with what it signs, so no slot of a client-CA seed is shown an RSA
/// leaf; and the ticket the resuming slot offers, whose sealed secret
/// derives from the transcript and whose bytes a refused resumption's
/// full handshake then signs, so no RSA session issues it.
fn slotShownRsa(harness: *const Harness, index: usize) bool {
    assert(index < tls_client_slots);
    const choice = expectedChoice(harness.tls_sni, harness.tls_names[index], harness.tls_scheme_offers[index]) orelse
        return false;
    if (choice == 0) return false;
    return sni_certificate_rsa[choice - 1];
}

/// The credentials behind choice `choice` of a #297 listener.
fn choiceCredentials(harness: *const Harness, choice: usize) *const zoxy.tls.Credentials {
    assert(choice < sni_choices_count);
    if (choice == 0) return &harness.tls_credentials[2].?;
    return &harness.tls_sni_credentials[choice - 1].?;
}

/// A leaf a client was shown is choice `choice`'s, octet for octet.
fn verifyShown(harness: *Harness, shown: []const u8, choice: usize) !void {
    if (!std.mem.eql(u8, shown, try leafPublicKey(harness.choiceCredentials(choice)))) {
        return error.TlsShownWrongCertificate;
    }
    harness.tls_choices_shown[choice] += 1;
    assert(harness.tls_choices_shown[choice] <= tls_client_slots + h3_clients_max);
}

/// A loaded certificate's leaf public key, read the way a client reads the
/// leaf it is shown, so the two compare octet for octet.
fn leafPublicKey(credentials: *const zoxy.tls.Credentials) ![]const u8 {
    assert(credentials.chain.len >= 1);
    const leaf: std.crypto.Certificate = .{ .buffer = credentials.chain[0], .index = 0 };
    const parsed = try leaf.parse();
    const key = parsed.pubKey();
    assert(key.len >= 65);
    return key;
}

fn startServerAndOrigins(harness: *Harness, arena: std.mem.Allocator, random: std.Random) !void {
    // Resolved by the library, as every build's options are: a seed whose
    // draws make a config zoxy would refuse fails here, by name, rather
    // than running a shape production cannot load.
    harness.config = try zoxy.config.resolve(arena, &harness.options);
    const options = harness.deriveInitOptions(random);
    try harness.server.init(arena, &harness.io, &harness.config, options);
    try harness.server.bindExtensions(&.{ .arena = arena });
    harness.tls_credentials = .{ null, null, null };
    if (harness.tls_clients >= 1) {
        // Index 2: the terminating listener is the third.
        harness.tls_credentials[2] = try zoxy.tls.Credentials.load(
            arena,
            zoxy.tls.testdata.cert_pem,
            zoxy.tls.testdata.key_pem,
            // The deterministic nonce is not optional here: without it the
            // CertificateVerify's DER length varies run to run, and with
            // it the trace this gate's verdict is that a seed replays.
            .{ .deterministic_nonce = true },
        );
        // One slot per listener, non-null exactly at the terminating one.
        harness.server.setTlsCredentials(
            harness.tls_credentials[0..harness.listeners_count],
        );
        if (harness.tls_sni) try harness.loadCertificateSet(arena);
    }
    if (harness.admin_scrapers.len > 0) harness.server.setAdminBind(admin_address);
    if (harness.dns_l4) try harness.startNameservers();
    try harness.server.start();

    harness.origin = .{
        .mode_selector = pickOriginMode,
        .context = harness,
        .expect_proxy_header = harness.proxy_protocol_send_l4 != null,
    };
    try harness.origin.start(&harness.io, Harness.originAddress());
    harness.origin_http = .{
        .mode_selector = pickHttpOriginMode,
        .context = harness,
        .forwarded_hops = &l7.scripts.forwarded_hops,
        // As `bareAddress` writes the peer `SimIo` gives every stream
        // client: the brackets and the port come off an IPv6 one.
        .observed_client = if (harness.io.client_ip6) "2001:db8:1::1" else "198.51.100.1",
        .client_cert_sha256 = zoxy.tls.testdata.client_cert_sha256,
    };
    harness.h2_origin = .{
        .tls = harness.http_protocol == .h2,
        .headers = &h2_origin_headers,
        .body = l7.canon.sized_body,
        // §8: a gRPC call is left to its deadline.
        .mute_path_prefix = l7.canon.grpc_mute_prefix,
        .health = harness.grpc_health,
        .picker = .{ .context = harness, .pick = pickH2Answer, .answered = countH2Answer },
    };
    // One of the two answers at the http endpoint's address — the address
    // the #178 pinned tag is minted from, so a sticky cookie names the same
    // endpoint whichever protocol reaches it.
    // On every seed, started or not: its zero counts are what the verdict
    // reads where no HTTPS cluster ran.
    harness.https_origin = .{ .response = l7.canon.sized_response };
    if (harness.http_protocol.http2()) {
        try harness.h2_origin.start(arena, &harness.io, &.{ .ip = Harness.httpOriginAddress() });
    } else if (harness.http_tls) {
        try harness.https_origin.start(arena, &harness.io, Harness.httpOriginAddress());
    } else {
        try harness.origin_http.start(&harness.io, Harness.httpOriginAddress());
    }
}

/// The terminating population's per-scenario state: the storage, the
/// slot bookkeeping the resuming client grows, and one echo token per
/// slot.
///
/// A plaintext seed draws nothing here, which is what keeps its stream
/// position — and so the whole sweep's plaintext coverage — exactly
/// where it was before TLS existed.
/// One client's script, drawn uniformly except that a clean seed never
/// gets `dribbled_head`.
///
/// The *original* reason is gone. #258 excluded it because an unfinished
/// request was an abort, and `verifyAccessLog`'s sharpest claim is that
/// a clean seed aborts nothing — an equality, and the one that fails on
/// seed 10 when #129's phantom-line bug is put back. #247 made the reap
/// answer `408`, so a dribbled head is now an ordinary answered exchange
/// and that objection no longer applies.
///
/// A different one does, and it was measured rather than assumed: clean
/// seeds pin the head budget to the idle window (`deriveHeadTimeoutMs`),
/// which can outlast the scenario's own backstop — so the reap does not
/// reliably land inside the run and seed 486 misses its golden `408`.
/// Including it here would want the clean budget drawn tight enough to
/// observe, which is a change to a value every clean seed shares for the
/// benefit of one script. Adversary seeds reach the axis already.
fn drawScript(random: std.Random, clean: bool) l7.Script {
    const drawn = random.enumValue(l7.Script);
    if (clean and drawn == .dribbled_head) return .get;
    return drawn;
}

fn populateTlsClients(harness: *Harness, random: std.Random) void {
    harness.tls_clients_storage = @splat(undefined);
    harness.tls_clients_live = harness.tls_clients;
    harness.tls_resume_started = false;
    harness.scenario_ended = false;
    harness.clock_jumped = false;
    harness.drop_kind = null;
    harness.drop_latch_armed = false;
    assert(harness.tls_clients <= tls_clients_max);
    // One token past the drawn count, for the resuming client's slot.
    const token_count = if (harness.tls_clients >= 1)
        harness.tls_clients + 1
    else
        0;
    assert(token_count <= tls_client_slots);
    for (harness.tls_tokens[0..token_count], 0..) |*token, index| {
        random.bytes(token);
        // A distinguishable first byte, so an echo oracle comparing the
        // wrong session's bytes fails on the first one rather than
        // needing the whole token to collide.
        token[0] = @intCast(index);
    }
}

/// One of the HTTP/2 population (#275): its streams drawn, and its end
/// counted with every other client's. A third of it floods instead, one
/// budget each (#276), so every one of the server's verdicts is reached
/// beside the exchanges it must not disturb.
fn prepareH2Client(harness: *Harness, random: std.Random) void {
    assert(harness.h2c_http);
    assert(harness.h2_count < clients_max);
    const salt = harness.h2_count;
    const client = &harness.h2_clients[harness.h2_count];
    harness.h2_count += 1;
    const streams = 1 + random.uintLessThan(u8, H2Client.streams_max);
    const floods = l7.H2Mode.floods;
    var mode: l7.H2Mode = if (random.uintLessThan(u8, 3) == 0)
        floods[random.uintLessThan(usize, floods.len)]
    else
        .exchange;
    // Its lines need the staging `h2_rapid_reset` sized for them.
    if (mode == .rapid_reset and !harness.h2_rapid_reset) mode = .exchange;
    // A fifth of exchanges break RFC 9113 once instead.
    const violates = harness.h2_violation_prng.random();
    const violation = violates.uintLessThan(u8, 5) == 0;
    const which = l7.H2Mode.violations[violates.uintLessThan(usize, l7.H2Mode.violations.len)];
    if (mode == .exchange and violation) mode = which;
    var plans: [H2Client.streams_max]l7.H2Plan = @splat(.{});
    for (plans[0..streams]) |*plan| {
        plan.* = drawH2Plan(random, harness.h2_consult_prng.random());
        // A sixth of streams ask the handler instead (#434): a GET as is,
        // and a POST of the handler's own payload, in one frame.
        const asks_handler = harness.h2_handler_prng.random().uintLessThan(u8, 6) == 0;
        const splits_cookie = harness.h2_handler_prng.random().uintLessThan(u8, 6) == 0;
        if (asks_handler) plan.* = handlerPlan(plan.*);
        // And a sixth of the origin's GETs split their cookie (§8.2.3).
        if (plan.ask == .get) plan.split_cookie = splits_cookie;
        if (!harness.http_protocol.http2()) continue;
        if (plan.ask != .post_declared) continue;
        if (harness.grpc_prng.random().uintLessThan(u8, 3) != 0) continue;
        plan.ask = .grpc_call;
        plan.trailers = false;
    }
    client.prepare(&harness.io, httpBindAddress(), plans[0..streams], salt, harness.clean, mode, harness.drawH2Tuning(mode));
    client.interim_owed = harness.interimOwed();
    client.on_ended = clientEndedHook;
    client.context = harness;
}

/// A throttled stream's window: under any canonical body, so a server
/// that honours it must stop part-way and wait for credit.
const h2_throttle_window: u32 = 5;

/// What an exchange client's opening SETTINGS ask: a third throttle
/// their streams to a few octets of window, granted more only once the
/// first DATA is back, and a third lower their HPACK table — to nothing,
/// or below the default — each independently. A flood's SETTINGS are its
/// budget's, so it asks for nothing.
fn drawH2Tuning(harness: *Harness, mode: l7.H2Mode) l7.H2Tuning {
    const random = harness.h2_tuning_prng.random();
    const throttle = random.uintLessThan(u8, 3) == 0;
    const table = random.uintLessThan(u8, 3);
    const goaway = random.uintLessThan(u8, 4) == 0;
    if (mode != .exchange) return .{};
    const tuning: l7.H2Tuning = .{
        .throttle_window = if (throttle) h2_throttle_window else null,
        .goaway = goaway,
        .header_table_size = switch (table) {
            0 => 0,
            1 => 256,
            else => null,
        },
    };
    assert(tuning.header_table_size orelse 0 < 4096);
    return tuning;
}

/// `plan` turned into its handler ask (#434): the same method, the build's
/// handler route, and for a POST the payload the handler reads.
fn handlerPlan(plan: l7.H2Plan) l7.H2Plan {
    if (!plan.carriesBody()) {
        const get: l7.H2Plan = .{ .ask = .handler_get };
        assert(!get.carriesBody());
        return get;
    }
    const handler: l7.H2Plan = .{
        .ask = .handler_post,
        .body_len = l7.canon.handler_post_payload.len,
        .frames = 1,
    };
    assert(handler.carriesBody());
    return handler;
}

/// One stream's request (#373): half are a GET, and half POST a marked
/// body, its length declared or not. A GET is `get`'s or `consult_get`'s
/// (#437), evenly, by a coin from `consult_random`, so no other draw of
/// the seed's moves for it. A body is short or up to the largest, evenly,
/// so seeds meet both one small frame and frames past a small relay
/// buffer's room. It is cut into up to `h2_body_frames_max` DATA frames,
/// and half of POSTs end their half with a trailer section instead of the
/// last frame's END_STREAM (§7).
fn drawH2Plan(random: std.Random, consult_random: std.Random) l7.H2Plan {
    if (random.boolean()) {
        const ask: l7.H2Ask = if (consult_random.boolean()) .consult_get else .get;
        return .{ .ask = ask };
    }
    const ask: l7.H2Ask = if (random.boolean()) .post_declared else .post_undeclared;
    const short_bytes_max: u32 = 64;
    const span = if (random.boolean()) short_bytes_max else l7.h2_body_bytes_max;
    const body_len = 1 + random.uintLessThan(u32, span);
    const frames_max: u8 = @intCast(@min(l7.h2_body_frames_max, body_len));
    const plan: l7.H2Plan = .{
        .ask = ask,
        .body_len = body_len,
        .frames = 1 + random.uintLessThan(u8, frames_max),
        // §7: a client's request trailers end its half and go no further.
        .trailers = random.boolean(),
    };
    assert(plan.frames <= plan.body_len);
    assert(plan.body_len <= l7.h2_body_bytes_max);
    return plan;
}

fn populateClients(harness: *Harness, random: std.Random) void {
    // Each client flips a protocol coin: mixed populations put both
    // serving paths under one schedule and shared pools.
    const plaintext_count = 1 + random.uintLessThan(u8, clients_max);
    // The terminating clients are part of the population the wind-down
    // waits on, so they join the count `clientEnded` compares against.
    harness.clients_count = plaintext_count + harness.tls_clients + harness.h3_count +
        @as(u8, @intCast(harness.admin_scrapers.len));
    harness.l4_count = 0;
    harness.l7_count = 0;
    harness.h2_count = 0;
    harness.ended_count = 0;
    harness.populateTlsClients(random);
    harness.clients = @splat(.{});
    harness.l7_clients = @splat(.{});
    harness.h2_clients = @splat(.{});
    harness.l4_announced_len = @splat(0);
    harness.l4_denied_count = 0;
    var index: u8 = 0;
    while (index < plaintext_count) : (index += 1) {
        if (random.boolean()) {
            // On a seed that speaks it, a share of the http population
            // speaks HTTP/2 (#275) to the same listener.
            if (harness.h2c_http and random.uintLessThan(u8, 3) == 0) {
                harness.prepareH2Client(random);
                continue;
            }
            const client = &harness.l7_clients[harness.l7_count];
            harness.l7_count += 1;
            // A seed that enables upgrades puts its first two http
            // clients on the handshake, rather than waiting for a
            // uniform draw over every script to produce one. It raises
            // the odds rather than guaranteeing them — the client count
            // and the per-slot coin still decide how many http clients a
            // seed has — but it is what makes two concurrent handshakes,
            // and so the §8 tunnel rung, ordinary across a sweep instead
            // of a coincidence. Every other client still draws freely,
            // so the population keeps its shape.
            const forced_upgrade = harness.upgrades_http and harness.l7_count < 2;
            client.prepare(
                &harness.io,
                httpBindAddress(),
                if (forced_upgrade)
                    .upgrade_request
                else
                    drawScript(random, harness.clean),
                harness.clean,
                harness.upgrades_http,
                harness.sticky_http,
            );
            client.interim_owed = harness.interimOwed();
            client.on_ended = clientEndedHook;
            client.context = harness;
        } else {
            const client = &harness.clients[harness.l4_count];
            const l4_index = harness.l4_count;
            harness.l4_count += 1;
            var token: [l4.token_bytes_max]u8 = undefined;
            const random_len = 1 + random.uintLessThan(u8, l4.random_token_bytes_max);
            random.bytes(token[0..random_len]);
            const silent = random.uintLessThan(u8, 5) == 0;
            const token_len = harness.drawHello(l4_index, silent, &token) orelse random_len;
            // A silent client sends nothing, header included: on a
            // require-listener it is the connect-budget reap's fodder,
            // and drawing it a header it would never send would teach
            // `verifyAccessLog` to demand an announcement that never
            // crossed the wire.
            var prefix_buffer: [l4.prefix_bytes_max]u8 = undefined;
            const prefix = if (silent)
                ""
            else
                harness.deriveProxyHeader(random, l4_index, &prefix_buffer);
            client.prepare(
                &harness.io,
                bindAddress(),
                token[0..token_len],
                prefix,
                silent,
            );
            client.on_ended = clientEndedHook;
            client.context = harness;
        }
    }
    harness.prepareH3Clients();
    assert(harness.l4_count + harness.l7_count + harness.h2_count + harness.tls_clients +
        harness.h3_count + harness.admin_scrapers.len == harness.clients_count);
}

/// The HTTP/3 population (#449): each client's requests drawn as HTTP/2's
/// streams are (`drawH2Plan`), from the HTTP/3 stream, its bodies within
/// what one write carries, and its connection's randomness from there too.
fn prepareH3Clients(harness: *Harness) void {
    const random = harness.h3_prng.random();
    assert(harness.h3_count <= h3_clients_max);
    for (harness.h3_clients[0..harness.h3_count], 0..) |*client, index| {
        const streams = 1 + random.uintLessThan(u8, H3Client.streams_max);
        var plans: [H3Client.streams_max]l7.H2Plan = @splat(.{});
        for (plans[0..streams]) |*plan| plan.* = drawH3Plan(random);
        var seed: [64]u8 = undefined;
        random.bytes(&seed);
        // A key share's private half may not be zero; one octet set is
        // enough to make sure of it.
        seed[32] |= 1;
        client.prepare(&harness.io, tlsBindAddress(), plans[0..streams], @intCast(index), harness.clean, seed, harness.h3_names[index]);
        client.interim_owed = harness.interimOwed();
        client.on_ended = clientEndedHook;
        client.context = harness;
    }
}

/// One HTTP/3 request (#449): `drawH2Plan`'s, its body held within what
/// one write of the client's carries.
fn drawH3Plan(random: std.Random) l7.H2Plan {
    var plan = drawH2Plan(random, random);
    if (!plan.carriesBody()) return plan;
    plan.body_len = @min(plan.body_len, l7.h3_body_bytes_max);
    plan.frames = @intCast(@min(plan.frames, plan.body_len));
    assert(plan.body_len >= 1);
    assert(plan.frames >= 1);
    return plan;
}

/// The header an L4 client opens with when the listener requires one
/// (#142), or "" — the gate off, or one draw in six sending nothing so
/// the sweep reaches the refusal too (the random token then opens the
/// stream, and `require` closes on its first byte; the rare token that
/// happens to open like a header meets the connect-budget reap instead).
/// The spread covers both spec versions, both address families and both
/// verdict families: announcing headers (v1 TCP4 and TCP6, v2 INET and
/// INET6) carry a per-client distinct address that is recorded for the
/// clean-seed log oracle — and, where the cluster sends a header on, for
/// the origin's, so an IPv6 client also makes the proxy write the TCP6
/// forms with an IPv4 destination mapped beside it — and non-announcing
/// ones (v1 UNKNOWN, v2 LOCAL) are the health-check shape that must keep
/// the observed peer.
fn deriveProxyHeader(
    harness: *Harness,
    random: std.Random,
    l4_index: u8,
    buffer: *[l4.prefix_bytes_max]u8,
) []const u8 {
    assert(l4_index < clients_max);
    assert(harness.l4_announced_len[l4_index] == 0);
    if (harness.proxy_protocol_l4 == null) {
        return "";
    }
    const octet: u8 = l4_index + 1;
    const port: u16 = 40_000 + @as(u16, l4_index);
    switch (random.uintLessThan(u8, 9)) {
        0 => return "",
        1 => return "PROXY UNKNOWN\r\n",
        2 => {
            // v2 LOCAL: a fronting proxy's health check.
            @memcpy(buffer[0..16], "\r\n\r\n\x00\r\nQUIT\n" ++ "\x20\x00\x00\x00");
            return buffer[0..16];
        },
        3 => {
            // v2 PROXY INET announcing 203.0.113.<octet>:<port>.
            @memcpy(buffer[0..16], "\r\n\r\n\x00\r\nQUIT\n" ++ "\x21\x11\x00\x0c");
            buffer[16..20].* = .{ 203, 0, 113, octet };
            buffer[20..24].* = .{ 10, 0, 0, 1 };
            std.mem.writeInt(u16, buffer[24..26], port, .big);
            std.mem.writeInt(u16, buffer[26..28], 443, .big);
            harness.recordAnnounced(l4_index, announced_network, octet, port);
            return buffer[0..28];
        },
        6 => {
            // v1 TCP4 from the network the connection policy refuses
            // (#425): logged as announced, never dialed.
            const line = std.fmt.bufPrint(
                buffer,
                "PROXY TCP4 192.0.2.{d} 10.0.0.1 {d} 443\r\n",
                .{ octet, port },
            ) catch unreachable; // 44 bytes at most, into 64.
            harness.recordAnnounced(l4_index, denied_network, octet, port);
            harness.l4_denied_count += 1;
            return line;
        },
        7 => {
            // v1 TCP6 announcing 2001:db8::<octet>:<port>.
            const line = std.fmt.bufPrint(
                buffer,
                "PROXY TCP6 2001:db8::{x} 2001:db8::1 {d} 443\r\n",
                .{ octet, port },
            ) catch unreachable; // 50 bytes at most, into 64.
            harness.recordAnnouncedV6(l4_index, octet, port);
            return line;
        },
        8 => {
            // v2 PROXY INET6 announcing the same.
            @memcpy(buffer[0..16], "\r\n\r\n\x00\r\nQUIT\n" ++ "\x21\x21\x00\x24");
            buffer[16..32].* = announcedV6Bytes(octet);
            buffer[32..48].* = announcedV6Bytes(1);
            std.mem.writeInt(u16, buffer[48..50], port, .big);
            std.mem.writeInt(u16, buffer[50..52], 443, .big);
            harness.recordAnnouncedV6(l4_index, octet, port);
            return buffer[0..52];
        },
        else => {
            // v1 TCP4, the same announcement in text.
            const line = std.fmt.bufPrint(
                buffer,
                "PROXY TCP4 203.0.113.{d} 10.0.0.1 {d} 443\r\n",
                .{ octet, port },
            ) catch unreachable; // 46 bytes at most, into 64.
            harness.recordAnnounced(l4_index, announced_network, octet, port);
            return line;
        },
    }
}

/// 2001:db8::<host>, the documentation prefix's (RFC 3849) host `host`.
fn announcedV6Bytes(host: u8) [16]u8 {
    assert(host >= 1);
    var bytes: [16]u8 = @splat(0);
    bytes[0..4].* = .{ 0x20, 0x01, 0x0d, 0xb8 };
    bytes[15] = host;
    assert(bytes[14] == 0);
    return bytes;
}

/// `recordAnnounced` for an IPv6 announcement, its text written out the
/// way RFC 5952 compresses it — not by the formatter the log itself
/// uses, so a log that rendered it some other way fails the oracle.
fn recordAnnouncedV6(harness: *Harness, l4_index: u8, octet: u8, port: u16) void {
    assert(l4_index < clients_max);
    assert(octet >= 1);
    const text = std.fmt.bufPrint(
        &harness.l4_announced[l4_index],
        "[2001:db8::{x}]:{d}",
        .{ octet, port },
    ) catch unreachable; // 19 bytes, into announced_bytes_max.
    // The host octet is `l4_index + 1`, at most `clients_max`, so one hex
    // digit, and the port five decimal ones.
    comptime assert(clients_max <= 0xf);
    assert(text.len == 19);
    harness.l4_announced_len[l4_index] = @intCast(text.len);
    harness.l4_announced_address[l4_index] = .{ .ip6 = .{ .bytes = announcedV6Bytes(octet), .port = port } };
}

fn recordAnnounced(harness: *Harness, l4_index: u8, network: [3]u8, octet: u8, port: u16) void {
    assert(l4_index < clients_max);
    const text = std.fmt.bufPrint(
        &harness.l4_announced[l4_index],
        "{d}.{d}.{d}.{d}:{d}",
        .{ network[0], network[1], network[2], octet, port },
    ) catch unreachable; // 19 bytes at most, into announced_bytes_max.
    // The shortest form is "192.0.2.1:40000"; anything outside the
    // templates' range means a format string drifted from the record.
    assert(text.len >= 15);
    assert(text.len <= 19);
    harness.l4_announced_len[l4_index] = @intCast(text.len);
    harness.l4_announced_address[l4_index] =
        .{ .ip4 = .{ .bytes = network ++ [1]u8{octet}, .port = port } };
}

pub fn startClients(harness: *Harness) void {
    assert(harness.clients_count >= 1);
    assert(harness.l4_count + harness.l7_count + harness.h2_count + harness.tls_clients +
        harness.h3_count + harness.admin_scrapers.len == harness.clients_count);
    for (harness.clients[0..harness.l4_count]) |*client| {
        client.begin();
    }
    for (harness.admin_scrapers) |*scraper| scraper.begin();
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        client.begin();
    }
    for (harness.h2_clients[0..harness.h2_count]) |*client| {
        client.begin();
    }
    for (harness.h3_clients[0..harness.h3_count]) |*client| {
        client.begin();
    }
    harness.startTlsClients();
}

/// The §4 population (#125). `TestClient.start` dials immediately rather
/// than splitting prepare from begin, so it runs here rather than in
/// `populateClients` — and its hook has to be set *after*, because `start`
/// clears both hook fields.
///
/// Every seed is drawn from the scenario stream, not from `fillRandom`:
/// the client's key material must not interleave with the server's on the
/// simulator's key stream, or the handshake count would decide what each
/// peer got and the replay would depend on delivery order.
fn startTlsClients(harness: *Harness) void {
    var index: u8 = 0;
    while (index < harness.tls_clients) : (index += 1) {
        const random = harness.scenario_prng.random();
        var seeds: [3][32]u8 = undefined;
        for (&seeds) |*seed| random.bytes(seed);
        harness.startTlsClient(index, &seeds, null);
    }
    if (harness.tls_clients == 0) return;
    const random = harness.scenario_prng.random();
    for (&harness.tls_resume_seeds) |*seed| random.bytes(seed);
}

/// One terminating client into slot `index`, offering `resume_with` if it
/// has one. Shared by the population and by the resuming client, so the
/// two differ in exactly the ticket and nothing else — which is what
/// makes a resumed session's coverage the same coverage, minus a full
/// handshake.
fn startTlsClient(
    harness: *Harness,
    index: u8,
    seeds: *const [3][32]u8,
    resume_with: ?*const zoxy.tls.SessionTicket,
) void {
    assert(index < harness.tls_clients_live);
    const client = &harness.tls_clients_storage[index];
    // What this slot drew, and the one property of it the session's shape
    // turns on: a script whose response is judged exactly as a plain
    // GET's can be followed by one (#204's keep-alive turnaround, judged
    // as `terminating_pair`), and one whose response is a static, a
    // redirect, a rejection or an un-stamped 200 cannot — a single spec
    // could not describe both halves of that pair.
    if (harness.slotSpeaksH2(index)) return harness.startTlsH2Client(index, seeds, resume_with);
    const entry = l7.scripts.spec(harness.tls_scripts[index]);
    const pairs = harness.tls_protocol == .http and entry.routed_canonical;
    client.start(&harness.io, Harness.tlsBindAddress(), .{
        .host_name = harness.tls_names[index],
        .scheme_offer = harness.tls_scheme_offers[index],
        .client_credentials = harness.clientIdentity(index),
        .resume_with = resume_with,
        .alpn = harness.tls_alpn_offers[index].protocols(),
        // An echo token for a relayed session, a real request for a
        // proxied one — the terminated stream has to be what the
        // listener behind it expects, or the head parser answers 400
        // and the transform is never exercised at all.
        .app_data = if (harness.tls_protocol == .http)
            entry.request
        else
            harness.tls_tokens[index][0..tls_token_bytes],
        // How each population knows its peer answered. A relayed
        // session gets its own bytes back, so a byte count is exactly
        // right; a proxied one gets a response, whose length has
        // nothing to do with its request's, so it needs the framing
        // rule (#204). Wiring the echo rule to the proxied population
        // would not fail — it would *hang*, waiting for a response as
        // long as the request that earned it.
        .exchange_end = if (harness.tls_protocol == .http)
            .http_response
        else
            .echo,
        // The second request, on the connection the first left open —
        // only the proxied population has one, since an echo has no
        // turnaround to take.
        .followup_data = if (pairs) tls_http_followup else &.{},
        // A relayed session closes in protocol once its echo is back:
        // an in-band EOF no socket EOF follows, which is the §6
        // half-close a terminated relay can only learn from a decrypt.
        // A paired one lets its second request's `Connection: close` end
        // the connection instead, and finishes on the EOF.
        //
        // An unpaired proxied session takes the relayed shape, and has
        // to: its script's request carries no `Connection: close`, so
        // without this the answered connection would sit in keep-alive
        // until the drain reaped it — holding a conn slot for the rest of
        // the scenario on a fifth of the terminating clients. Closing in
        // protocol instead is the §6 half-close arriving mid-keep-alive,
        // which nothing else in the sweep produces.
        .close_after_echo = !pairs,
        .x25519_seed = seeds[0],
        .p256_seed = seeds[1],
        .random = seeds[2],
    }) catch unreachable; // Seeded keypairs; the inputs are ours.
    // A fresh session holds nothing yet: whatever ticket this slot's
    // previous occupant captured must not survive into the next one, and
    // on the resuming slot that is the difference between offering the
    // issuer's ticket and offering its own.
    assert(client.capturedTicket() == null);
    client.on_end = tlsClientEndedHook;
    client.on_end_context = harness;
}

/// An HTTP/2 TLS slot (`slotSpeaksH2`): the session sends its exchange's
/// whole flight once up, and ends — closing in protocol — when every
/// stream has, as `tls_h2_clients` judges what came back.
fn startTlsH2Client(
    harness: *Harness,
    index: u8,
    seeds: *const [3][32]u8,
    resume_with: ?*const zoxy.tls.SessionTicket,
) void {
    harness.prepareTlsH2Client(index);
    const exchange = &harness.tls_h2_clients[index];
    const client = &harness.tls_clients_storage[index];
    client.start(&harness.io, Harness.tlsBindAddress(), .{
        .host_name = harness.tls_names[index],
        .scheme_offer = harness.tls_scheme_offers[index],
        .client_credentials = harness.clientIdentity(index),
        .resume_with = resume_with,
        .alpn = harness.tls_alpn_offers[index].protocols(),
        .app_data = exchange.flight(),
        .exchange_end = .judged,
        .judge = .{ .context = exchange, .complete = H2Client.judgeComplete },
        .close_after_echo = true,
        .x25519_seed = seeds[0],
        .p256_seed = seeds[1],
        .random = seeds[2],
    }) catch unreachable; // Seeded keypairs; the inputs are ours.
    assert(client.capturedTicket() == null);
    client.on_end = tlsClientEndedHook;
    client.on_end_context = harness;
}

/// #204's resumption leg. A ticket can only be offered on a *second*
/// connection, so this runs off the first one's end: whichever session
/// captured a ticket, its ticket goes back out on a fresh dial, and the
/// server's `psk_lookup` either opens what it sealed or falls back to a
/// full handshake. Both are legal, which is why the counter is the
/// oracle and not this call succeeding.
///
/// `clients_count` grows *before* `clientEnded` compares against it, so
/// the wind-down waits for the resuming session rather than racing it.
fn maybeStartResumingClient(harness: *Harness) void {
    // The hook is wired to terminating clients only, so reaching here at
    // all means the seed drew some — which is what stops the slot index
    // below from underflowing.
    assert(harness.tls_clients >= 1);
    if (harness.tls_resume_started) return;
    // The wind-down has stopped the listener accepting, so a dial now
    // would only ever measure how a refused connect is reaped.
    if (harness.scenario_ended) return;
    const issuer = harness.ticketIssuer() orelse return;
    const ticket = issuer.capturedTicket().?;
    harness.tls_resume_started = true;
    harness.tls_clients_live += 1;
    harness.clients_count += 1;
    // Exactly one resumer, in exactly the slot past the drawn count —
    // today only the `tls_resume_started` latch keeps that true, so it is
    // worth saying out loud rather than inferring from the latch.
    assert(harness.tls_clients_live == harness.tls_clients + 1);
    assert(harness.tls_clients_live <= tls_client_slots);
    harness.startTlsClient(harness.tls_clients_live - 1, &harness.tls_resume_seeds, ticket);
}

/// The first finished session holding a ticket. A server issues them on
/// every handshake, so this is normally the first client to end — but a
/// refused dial, a cut handshake or a shed engine all end a client with
/// nothing to offer, and on those seeds there is simply no resumption to
/// cover.
fn ticketIssuer(harness: *Harness) ?*TlsClient {
    // The drawn population only: the resuming client's own ticket is
    // never offered again, and its slot may not even exist yet.
    assert(harness.tls_clients >= 1);
    assert(harness.tls_clients <= harness.tls_clients_live);
    for (harness.tls_clients_storage[0..harness.tls_clients], 0..) |*client, index| {
        if (!client.isEnded()) continue;
        // Never a session an RSA leaf signed (`rsaSaltContained`).
        if (harness.slotShownRsa(index)) continue;
        if (client.capturedTicket() != null) return client;
    }
    return null;
}

fn tlsClientEndedHook(context: ?*anyopaque) void {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    // Before the resumer dials, so its handshake is the one that finds
    // the key overdue and its offered ticket the one sealed under the key
    // being retired.
    harness.maybeJumpClock();
    harness.maybeStartResumingClient();
    harness.clientEnded();
}

fn clientEnded(harness: *Harness) void {
    harness.ended_count += 1;
    assert(harness.ended_count <= harness.clients_count);
    if (harness.ended_count == harness.clients_count) {
        harness.endScenario();
    }
}

/// #206's first hook, on the seeds that drew `.wind_down`: take every
/// armed op of one kind and never deliver it, at the instant the
/// wind-down begins. That is the class of defect no other seed can reach
/// — everything else this simulator does completes, which is faithful to
/// io_uring and blind to what a readiness backend did in #203.
///
/// At the wind-down because that is where the ops worth stranding are
/// armed. Measured over a 4096-seed sweep, the share of wind-downs
/// holding at least one op of a kind: timer 98%, accept 98%, recv 53%,
/// connect 24%, log_write 24%, timer_cancel 15%, recv_group 10%, send
/// 1.2%, connect_cancel 1.0% — and `close` on none of them.
///
/// The kind is picked here, out of what is armed, rather than drawn with
/// the rest of the topology, and the spread above is why. A kind named
/// before the run spends its seed whether or not the wind-down holds one:
/// 230 of the 368 runs that drew a kind found none of it armed and
/// stranded nothing, and the kinds armed under a fifth of the time were
/// out of reach in practice — a blind draw finds `send` armed about once
/// in five sweeps. Picking from the armed set makes every drawn run
/// strand: 316 strands against 124, and 112 runs reaching the §8 give-up
/// against 52. What it costs is a seed's strand being settled before the
/// run starts, which nothing needed — `verify` reads what was stranded,
/// never what was going to be.
///
/// Uniform over *kinds* rather than over pending *ops*, deliberately:
/// accept and timer are four fifths of everything pending, so picking a
/// random op would spend nearly every strand on those two and reach
/// recv_group about once in a sweep.
fn maybeStrandOps(harness: *Harness) void {
    if (harness.drop_mode != .wind_down) return;
    if (harness.drop_kind != null) return;
    if (!harness.giveUpCanExist()) return;
    const kind = harness.drawStrandKind() orelse return;
    const dropped = harness.io.dropPendingOps(kind);
    // The kind came out of the armed set, so a strand that took nothing is
    // a contradiction rather than the legal outcome it used to be: either
    // the pick read a table the drop then disagreed with, or an op left
    // the table between the two calls — and nothing runs in between.
    assert(dropped >= 1);
    // A stranded op stays *pending*, so the table it was counted out of is
    // still the bound; more than that would mean one was counted twice.
    assert(dropped <= harness.io.pending_count);
    // What the seed *did*, which is the fact `verify` reads — recorded
    // after the drop rather than before it, because the excuse it grants
    // ("this run may end at the give-up") is earned by stranding.
    harness.drop_kind = kind;
}

/// #206's second hook, on the seeds that drew `.teardown`: strand the
/// first cancel submitted once the drain is already under way, rather
/// than one that was in flight when it began.
///
/// This is the half a wind-down drop cannot reach, and the issue's own
/// argument for it was wrong the first time round, so it is worth being
/// exact. It is *not* that a slot which can never be released is
/// otherwise unreachable — stranding any conn-armed op leaves one, 76
/// runs a sweep do it. It is that `beginTeardown` arms `connect_cancel`
/// and `deadline_cancel` *after* a wind-down drop has landed, so those
/// two are the only ops in a connection's armed set no drop placed at the
/// wind-down can be holding. #203 was a cancel submitted and never
/// delivered; this hook models it where it happened.
///
/// It waits rather than takes, which is the difference from
/// `drawStrandKind`: an op armed later is in no table to be read now, so
/// this hook cannot know whether it will find anything. Measured over a
/// 4096-seed sweep, 246 of the 784 runs that draw it find a cancel to
/// take; the other 538 are held to the ordinary invariants, having taken
/// nothing. That is the price of reaching an op that does not exist yet,
/// and the mode is drawn twice as often as `.wind_down` to pay it.
///
/// What it buys is the sharpest signal in this issue: **all 246 reach the
/// §8 give-up**, against 112 of the 316 wind-down strands, and 168 of
/// them leave the *connection* plane stuck. A cancel armed during
/// teardown and never delivered leaves that connection's armed set
/// non-empty forever, and `continueTeardown` returns early for as long as
/// that is true — a connection stuck in teardown with its slot held,
/// which is #203 exactly. The other 78 are the prober's, which cancels a
/// dial of its own when the drain stops it.
///
/// **Where it is armed decides what it catches**, which took two
/// measurements to get right and is the sort of thing that rots quietly.
/// Per run that drew the mode, and per strand it took:
///
///   - Armed *before* the doubles' `cancelIfStuck` burst: 82% strand, but
///     a fifth of those took a client double's cancel — the server's
///     drain never waits on one, so the run drained clean and the strand
///     bought nothing.
///   - Armed after the doubles and *before* `beginDrain` returns: 75%
///     strand, and 7% of those land on conns. The prober's stop-cancel is
///     submitted first, from inside the drain, and takes the other 93%.
///   - Armed after `beginDrain` returns: 31% strand, and 68% of those land
///     on conns.
///
/// The last is what ships. It strands on fewer runs because the cancels
/// submitted from inside the drain are gone by then, and that is the
/// point: what is left is the teardown of a connection that was still
/// working when the drain started. Armed at both drain entries, since a
/// seed that drains mid-scenario tears its connections down there.
fn armTeardownStrand(harness: *Harness) void {
    if (harness.drop_mode != .teardown) return;
    if (harness.drop_latch_armed) return;
    if (!harness.giveUpCanExist()) return;
    // Nothing can have been stranded yet: the wind-down hook does not run
    // in this mode, and the latch itself takes nothing until a submit
    // answers it.
    assert(harness.strandedKind() == null);
    harness.drop_latch_armed = true;
    // Both kinds at once, not one drawn of the two: `beginTeardown` arms
    // whichever the connection's state calls for, and a latch naming the
    // other spends the whole scenario waiting for an op that never comes.
    harness.io.armDropNext(&teardown_strand_kinds);
}

/// Whether this seed's drain has a give-up to provoke at all. A zero
/// `drain_deadline_ms` is "no cap" (§5), and the deadline timer is the
/// only thing that ever arms one: `onDrainStuck` is started by
/// `onDrainDeadline`, so a drain with no deadline has no backstop.
/// Stranding an op there asks the proxy for a report the configuration
/// deliberately declined — the drain waits for the last connection
/// however long that takes, by design — and the run ends in `SimIo`'s own
/// deadlock with no diagnostic, which is the same shape the excluded
/// `timer` kind has and just as much a true statement about the
/// backstop's reach rather than a defect.
///
/// Asked at the strand rather than at the draw because the draw runs in
/// `deriveTerminatingDraws` and the deadline is settled one call later in
/// `deriveServerConfig`. Gating the draw needs the deadline first, and
/// swapping two calls re-rolls every draw after them for the whole sweep,
/// taking the §9 census margins with it. Skipping here leaves both hooks
/// having taken nothing, so `verify` holds the seed to the ordinary
/// invariants — exactly what a seed that stranded nothing is for.
///
/// Found by the nightly soak (run #18, 2026-08-13). All four shards hit
/// the 16-failure cap early in their slices — shard 0 at 36k — and every
/// named seed had drawn both a mid-scenario drain with the no-cap
/// deadline and a drop.
fn giveUpCanExist(harness: *const Harness) bool {
    assert(harness.drop_mode != null);
    return harness.config.drain_deadline_ms != 0;
}

/// One kind out of those armed at this wind-down, or null when nothing
/// strandable is armed at all.
///
/// Nothing is excluded any more, and `timer` leaving the exclusion list is
/// what #226 bought. Stranding one used to be the shape §8's backstop
/// provably could not catch — `onDrainStuck` was itself a timer, so a seed
/// that stranded the drain deadline stranded the thing that would have
/// reported it, and the run ended in `SimIo`'s deadlock with no diagnostic
/// at all. The watchdog under it is not an op (`alarmStart`), so it fires
/// whether or not the backend is still delivering, and the same seeds now
/// end in a give-up that says so.
///
/// `close` is here for a different reason and was never an exclusion: it
/// is simply not armed at a wind-down on any measured run, and an
/// armed-set pick spends nothing on a kind that is not there. Its absence
/// is a property of the teardown path — `continueTeardown` waits for
/// `armedCount()` to reach zero and closes *synchronously*, so a
/// connection never has a close to take away — and the admin plane's
/// `submitClose` is the only `io.close` in the proxy.
///
/// Drawn from the scenario stream at the wind-down, so it consumes nothing
/// on the seeds that strand nothing and leaves their stream position — and
/// with it the whole sweep's coverage — where it was.
fn drawStrandKind(harness: *Harness) ?SimIo.OpKind {
    // Adding a kind here needs a matching arm in `strandCanExplainStuck`,
    // which lists `timer` and `none` as `unreachable`: without one the new
    // kind panics every seed that strands it, which is the loudest way to
    // ask whoever adds it which planes it can leave stuck.
    const strandable = [_]SimIo.OpKind{
        .accept,
        .connect,
        .recv,
        .recv_group,
        .send,
        .close,
        .log_write,
        .timer,
        .timer_cancel,
        .connect_cancel,
    };
    var armed: [strandable.len]SimIo.OpKind = undefined;
    var armed_count: usize = 0;
    for (strandable) |kind| {
        if (!harness.io.hasPendingOp(kind)) continue;
        armed[armed_count] = kind;
        armed_count += 1;
    }
    assert(armed_count <= armed.len);
    if (armed_count == 0) return null;
    const kind = armed[harness.scenario_prng.random().uintLessThan(usize, armed_count)];
    // The pick is the whole point: a kind returned here is one the strand
    // that follows can actually take.
    assert(harness.io.hasPendingOp(kind));
    return kind;
}

/// What a seed that ended at the §8 give-up owes instead of the ordinary
/// invariants (#206). A seed that stranded an op the drain waits on
/// cannot finish it and must not be asked to; what is demanded is that
/// the proxy *noticed*. A drain that cannot complete is allowed, a drain
/// that hangs without saying so is not.
///
/// Reached as an alternative for every seed rather than a branch on
/// whether this one dropped anything, because that is the property worth
/// holding: no schedule, dropped op or not, may end with the loop alive
/// and nobody the wiser.
///
/// Split from `verify` when the two oracles below took it to the 70-line
/// limit — the same remedy `setUp` and `deriveTopology` took before it.
/// `pending_ops_live` is passed in rather than asked here because it has
/// to be read before `verify` closes the harness's own sockets.
fn verifyGaveUp(harness: *const Harness, code: u8, pending_ops_live: bool) !void {
    const watchdog = code == ServerSim.drain_watchdog_exit_code;
    if (code != ServerSim.drain_stuck_exit_code and !watchdog) {
        return error.UnexpectedAbort;
    }
    // Only a seed that stranded something is excused. Without this, the
    // branch would accept any stuck drain as "#206 working as intended" —
    // including one a future release bug produced with every op
    // delivered, which is the exact defect this backstop exists to catch
    // and the last thing the sweep should swallow.
    if (harness.strandedKind() == null) return error.DrainStuckWithoutStrand;
    // The give-up is allowed to leave work unfinished. It is not allowed
    // to have freed a slot an op still points at: that is the §5
    // corruption the generation counter exists to catch, and this is the
    // one path where it could hide, since a dropped op never reaches the
    // stale-handle assert every delivered op passes through. #206 asked
    // for this oracle by name.
    if (!pending_ops_live) return error.SlotReleasedUnderPendingOp;
    if (watchdog) return harness.verifyWatchdogGaveUp();
    if (!harness.strandCanExplainStuck()) return error.StrandCannotExplainStuck;
}

/// What the #226 watchdog owes when it is the thing that gave up.
///
/// Not `strandCanExplainStuck`: that oracle asks which plane the drain was
/// waiting on, and reaching this code means nobody was in a position to
/// ask. The loop stopped delivering, so the planes' states are whatever
/// the schedule left them as, and demanding one be stuck would be
/// demanding the wedged process have finished thinking.
///
/// What is demanded instead is that the give-up was the watchdog's — the
/// alarm actually fired, rather than some other path exiting with its
/// code — and that only a stranded *timer* can reach it. That second one
/// is the layering, stated where it breaks: every other kind leaves the
/// drain's own deadline delivering, so `onDrainStuck` fires at the grace
/// and reports the plane, five virtual seconds before the watchdog would.
/// A watchdog fire on any other kind means the informative layer stayed
/// silent when it could have spoken.
fn verifyWatchdogGaveUp(harness: *const Harness) !void {
    if (!harness.io.alarmFired()) return error.WatchdogCodeWithoutWatchdog;
    if (harness.strandedKind() != .timer) return error.WatchdogBeatTheReporter;
}

/// What this seed actually stranded, by whichever hook took it, or null
/// for the seeds that stranded nothing — the fact `verify` reads when it
/// decides whether a stuck drain was asked for. The wind-down drop
/// records its kind on the harness; the teardown latch records its in the
/// backend, because what it took was decided by a submit that happened
/// long after the hook ran.
fn strandedKind(harness: *const Harness) ?SimIo.OpKind {
    const latched = harness.io.droppedNextOp();
    // The modes are alternatives, never both: one draw picks one hook, so
    // a seed with two strands would mean a hook ran outside its mode.
    assert(harness.drop_kind == null or latched == null);
    if (harness.drop_kind != null) assert(harness.drop_mode == .wind_down);
    if (latched) |kind| {
        assert(harness.drop_mode == .teardown);
        assert(kind == .timer_cancel or kind == .connect_cancel);
    }
    return harness.drop_kind orelse latched;
}

/// Whether the strand this seed took could account for a plane the
/// give-up found stuck. Mis-blaming is not hypothetical: the first
/// `onDrainStuck` reported "nothing stuck" while the admin plane held an
/// armed accept (#203), and a backstop that names the wrong plane sends
/// an operator somewhere useless with the process already gone.
///
/// Deliberately permissive — it asks that *some* stuck plane could own an
/// op of the stranded kind, never that a named one is stuck. Which plane a
/// strand lands on is a property of the schedule, and an oracle that
/// pinned it would fail on the rare seed rather than on a defect. That
/// bill was just paid once: #220's deadlock was a gate demanding an
/// outcome the configuration had declined.
///
/// Measured over a 4096-seed sweep, for the shape rather than the rule —
/// which plane each wind-down strand left stuck, in runs: `recv` conns 46,
/// `log_write` the log 24, `timer_cancel` conns 12 and conns+health 2,
/// `connect` health 10 and conns 4, `recv_group` conns 10, `send` conns 2,
/// `connect_cancel` conns 2. `accept` never leaves anything stuck at all —
/// 88 strands, no give-up — and admin is never the stuck plane. The
/// teardown latch adds 246 runs of its own: 168 on conns, the shape it
/// exists for, and 78 on the prober's dial cancel.
fn strandCanExplainStuck(harness: *const Harness) bool {
    const kind = harness.strandedKind().?;
    // Only `verifyGaveUp` calls this, and only after both of its own
    // gates: the run ended at an abort, and this seed stranded something.
    assert(harness.io.abortedWith() != null);
    const conns_stuck = !harness.server.conns.isFullyReleased();
    const admin_stuck = !harness.server.admin.isQuiescent();
    const log_stuck = !harness.server.access_log.isQuiescent();
    // The resolver (#481) is reported with the prober, as `onDrainStuck`
    // reports it: a background plane, waited on by the drain alike.
    const health_stuck = !harness.server.health.isQuiescent() or !harness.server.resolver.isQuiescent();
    // The HTTP/2 origin connections (#275); QUIC's endpoints are reported
    // with them, though no strand kind here can hold one.
    const origins_stuck = !harness.server.h2_origins.isFullyReleased();
    // `onDrainStuck` aborts only when a plane is unfinished, so a give-up
    // with every plane done is the backstop firing at nothing.
    assert(conns_stuck or admin_stuck or log_stuck or health_stuck or origins_stuck);
    return switch (kind) {
        // The head ring is the connection path's alone (§5).
        .recv_group => conns_stuck,
        // Nothing but the access log writes one.
        .log_write => log_stuck,
        // Connections read, the admin plane reads its scrape, and the
        // prober reads its probe; all three dial except the admin one, and
        // all three write.
        // An HTTP/2 origin connection reads, writes and dials too.
        .recv, .send => conns_stuck or admin_stuck or health_stuck or origins_stuck,
        .connect => conns_stuck or health_stuck or origins_stuck,
        // A listener's accept feeds admission and the admin plane.
        .accept => conns_stuck or admin_stuck,
        // Timers, and the cancels that chase them, belong to a conn's
        // deadline, the prober's pacing or the admin plane's scrape. The
        // access log arms none, which is why it is absent from both.
        .timer, .timer_cancel => conns_stuck or admin_stuck or health_stuck or origins_stuck,
        // Only those that dial can have a connect to cancel.
        .connect_cancel => conns_stuck or health_stuck or origins_stuck,
        // `submitClose` is the proxy's only `io.close`, and it is the admin
        // plane's; a connection's closes are `closeNow`, which leaves no
        // completion to strand. No seed has reached this arm — `close` has
        // never been armed at a wind-down — and it is written out anyway,
        // because the alternative is an exclusion list, and
        // `drawStrandKind` records why this hook no longer keeps one.
        .close => admin_stuck,
        // Out of `drawStrandKind`'s list, so unreachable rather than
        // defaulted: adding one there without giving it an arm here panics
        // every seed that strands it, and a named arm is what makes that
        // obvious to whoever adds the next kind.
        .none => unreachable,
        // #449's datagram ops: out of `drawStrandKind`'s list, since no
        // seed binds a QUIC listener yet — unreachable on the same terms.
        .recv_from, .send_to, .datagram_cancel => unreachable,
    };
}

/// Where this seed strands, or null for the thirteen in sixteen
/// adversarial seeds that strand nowhere. A small fraction on purpose — a
/// stranded run trades every other oracle for the one it exists to check,
/// since a drain that cannot finish leaves pools held and counters
/// unreconciled by design. Which kind is taken is not decided here;
/// `drawStrandKind` and `armDropNext` take what the schedule armed.
///
/// One draw for both modes, and `.wind_down` keeps the value that used to
/// mean "strand": the sweep's whole stream position hangs off how many
/// values are drawn here, so widening this into a second draw would
/// re-roll every seed after it and take the §9 census margins with it.
/// `.teardown` gets two of the sixteen values to `.wind_down`'s one,
/// because it strands on under a third of the seeds that draw it — see
/// `armTeardownStrand` for why that is a property of what it waits for
/// rather than a fixable one. The two hooks end up perturbing comparable
/// numbers of runs: 316 wind-down strands a sweep against 246.
fn deriveDropMode(clean: bool, random: std.Random) ?DropMode {
    // Adversarial seeds only, for the reason every sibling draw states:
    // a clean seed's oracle is each script's exact golden outcome, and a
    // stranded op ends the run at the give-up before those oracles are
    // reached — for every client in the scenario, not just the one the
    // strand touched. A silently unanswered exchange passing as "the
    // backstop worked" is precisely what clean seeds exist to forbid.
    if (clean) return null;
    return switch (random.uintLessThan(u8, 16)) {
        0 => .wind_down,
        1, 2 => .teardown,
        else => null,
    };
}

/// #202, on the seeds that drew it: step the wall clock past a sealing
/// key's whole rotation interval while the loop's own clock keeps
/// ticking. The next handshake to seal a ticket finds its key overdue and
/// replaces it — the only way a sweep whose scenarios last a virtual
/// second reaches a bound measured in hours.
///
/// Hung off the first terminating session *ending*, not off a virtual
/// instant. Virtual time only advances when a timer comes due, so a whole
/// population can handshake, exchange and close at the same instant — a
/// timer-driven jump measured 9 rotations across the entire sweep,
/// because it fired long after every seal it was meant to precede. This
/// placement measures 198.
///
/// What it covers, measured rather than assumed: a rotation under the
/// adversary's schedules, and a ticket carried across a jump longer than
/// its own lifetime failing to resume: 372 runs fail that way, against
/// 384 unjumped runs that resume. It does *not* cover the two-slot
/// property — a key
/// opening after it has stopped sealing — and cannot, with one jump. One
/// clock ages the key and the ticket together, so a jump big enough to
/// retire a six-hour key also ages every outstanding ticket past its one
/// hour. Reaching that state needs the key old and the ticket young: two
/// jumps, one before the seal and a smaller one after, landing inside the
/// window where the ticket is still valid and its key no longer seals.
/// Left undone deliberately; `src/tls/Tickets.zig` pins it directly.
fn maybeJumpClock(harness: *Harness) void {
    if (!harness.clock_jump_wanted) return;
    if (harness.clock_jumped) return;
    harness.clock_jumped = true;
    harness.io.advanceWallClock(clock_jump_ns);
}

/// Belt and suspenders: fires even if some client never ends (a
/// black-holed connect, a stuck exchange) and force-ends the run. Its
/// sentence spent a while attached to the wrong function — restored here
/// rather than deleted, because "some client never ends" is exactly the
/// case #206 now creates on purpose.
fn onScenarioEnd(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    harness.endScenario();
}

fn endScenario(harness: *Harness) void {
    harness.maybeStrandOps();
    harness.scenario_ended = true;
    for (harness.clients[0..harness.l4_count]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.h2_clients[0..harness.h2_count]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.h3_clients[0..harness.h3_count]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.tls_clients_storage[0..harness.tls_clients_live]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.admin_scrapers) |*scraper| scraper.cancelIfStuck();
    if (harness.dns_l4) {
        for (&harness.nameservers) |*nameserver| nameserver.stop();
    }
    harness.server.beginDrain();
    harness.armTeardownStrand();
    harness.origin.stopListening();
    harness.origin_http.stopListening();
    if (harness.http_protocol != .http1) harness.h2_origin.stopListening();
    if (harness.http_tls) harness.https_origin.stopListening();
}

/// Free what the arena cannot (§4): a `Credentials` owns a libcrypto key
/// object, which is not arena memory, so a sweep that only reset the
/// arena would leak one key per seed — twice over, since every seed runs
/// twice for the determinism check.
pub fn tearDown(harness: *Harness) void {
    for (&harness.tls_client_identities) |*slot| {
        if (slot.*) |*credentials| {
            credentials.deinit();
            slot.* = null;
        }
    }
    for (&harness.tls_sni_credentials) |*slot| {
        if (slot.*) |*credentials| {
            credentials.deinit();
            slot.* = null;
        }
    }
    for (&harness.tls_credentials) |*slot| {
        if (slot.*) |*credentials| {
            credentials.deinit();
            slot.* = null;
        }
    }
    for (harness.tls_clients_storage[0..harness.tls_clients_live]) |*client| {
        client.deinit();
    }
}

pub fn verify(harness: *Harness) !void {
    // #206: asked *before* the cleanup below, and the order is the whole
    // point. A strand takes harness-side ops too — the doubles and the
    // clients arm recvs of their own — and the tidying closes their
    // sockets, so asking afterwards reads the harness putting its own
    // things away as the server having freed a slot under a live
    // reference. Measured on seed 591: live before the cleanup, stale
    // after, with nothing wrong in between. What the oracle is about is
    // the state the run ended in, not the state the tidying leaves.
    const pending_ops_live = harness.io.pendingOpsReferenceLiveSockets();
    // The loop may stop before harness-side terminal completions
    // deliver; close what remains so the socket-leak check is exact.
    for (harness.clients[0..harness.l4_count]) |*client| {
        client.closeIfOpen();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        client.closeIfOpen();
    }
    for (harness.h2_clients[0..harness.h2_count]) |*client| {
        client.closeIfOpen();
    }
    for (harness.h3_clients[0..harness.h3_count]) |*client| {
        client.closeIfOpen();
    }
    for (harness.admin_scrapers) |*scraper| scraper.closeIfOpen();
    harness.origin.closeRemaining();
    harness.origin_http.closeRemaining();
    if (harness.http_protocol != .http1) harness.h2_origin.closeRemaining();
    if (harness.http_tls) harness.https_origin.closeRemaining();

    if (harness.io.abortedWith()) |code| {
        return harness.verifyGaveUp(code, pending_ops_live);
    }
    if (!harness.server.isIdle()) return error.PoolLeak;
    if (!harness.server.reconcile()) return error.CountersDiverged;
    // #423: every pick either picker made completed, exactly once.
    for (&harness.pickers) |*picker| {
        if (picker.completions != picker.calls) return error.PickNotCompleted;
    }
    // #429: every request either policy handed on completed, exactly once.
    for ([_]*const zoxy.testing.ScriptedPolicy{ &harness.policy_listener, &harness.policy_route }) |policy| {
        if (policy.completions != policy.handedOn()) return error.PolicyNotCompleted;
    }
    // #425: the connection policy refuses only clients that announced a
    // denied address — and on a clean seed, whose headers always complete,
    // every one of them.
    const refused = harness.connection_policy.refused;
    if (refused > harness.l4_denied_count) return error.ConnectionPolicyRefusedUnannounced;
    if (harness.clean and refused != harness.l4_denied_count) return error.ConnectionPolicyMissedDenied;
    // And every connection it let on completed, exactly once, by release.
    const connection_policy = &harness.connection_policy;
    if (connection_policy.completions != connection_policy.proceeded()) return error.ConnectionPolicyNotCompleted;
    if (!harness.io.sockets.isFullyReleased()) return error.SocketLeak;
    // §7: no malformed byte may ever reach an origin.
    if (harness.origin_http.violations != 0) return error.OriginSawMalformedBytes;
    // #373: a marked body reaches its origin exactly as its client sent it.
    if (harness.origin_http.body_mismatches != 0) return error.OriginSawWrongBody;
    // §7: a request's trailer section reaches its origin iff its head owed
    // one — relayed whole from HTTP/1.1, never from HTTP/2 or HTTP/3, and
    // never one that names a header the proxy manages.
    if (harness.origin_http.trailer_mismatches != 0) return error.OriginSawWrongTrailers;
    // #275, §8: the HTTP/2 origin answered or reset every stream it took;
    // one dropped for want of a job would read as the proxy's silence.
    if (harness.h2_origin.requests_dropped != 0) return error.H2OriginDroppedRequest;
    // #296: what the HTTPS origin decrypted was every time a request.
    if (harness.https_origin.violations != 0) return error.OriginSawMalformedBytes;
    // §7: a forwarded-for chain holds the scripts' hops and, last, the
    // client the proxy observed, written bare in either family.
    if (harness.origin_http.forwarded_mismatches != 0) return error.OriginSawWrongForwardedFor;
    if (harness.origin_http.cookie_mismatches != 0) return error.OriginSawCookieUnjoined;
    // §4: a verified client's fingerprint, once, and no forgery or stale one.
    if (harness.origin_http.client_cert_mismatches != 0) return error.OriginSawWrongClientCert;
    // #142 send: on any seed, garbage where a header belongs is zoxy's
    // bug — the writers are pure and the adversary splits deliveries but
    // never corrupts bytes, so a cut lands as EOF, not as a violation.
    if (harness.origin.proxy_header_violations != 0) {
        return error.OriginSawInvalidProxyHeader;
    }
    try harness.verifyUpstreamIdentities();
    try harness.verifyStickyCounters();
    try harness.verifyAccessLog();
    for (harness.clients[0..harness.l4_count]) |*client| {
        try client.verifyIntegrity();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        try client.verify();
    }
    for (harness.h2_clients[0..harness.h2_count]) |*client| {
        try client.verify();
    }
    const max_lifetime_ns = @as(u64, harness.server.config.max_lifetime_ms) * std.time.ns_per_ms;
    for (harness.h3_clients[0..harness.h3_count], 0..) |*client, index| {
        try client.verify(max_lifetime_ns);
        try harness.verifyH3Certificate(client, index);
    }
    for (harness.admin_scrapers) |*scraper| try scraper.verify(&harness.server.counters);
    try harness.verifyTlsSessions();
    try harness.verifyClientRefusalCount();
    try harness.verifySniCounters();
    try harness.verifyDnsSet();
    try harness.verifyGrpcHealth();
}

/// Whether a seed's gRPC health answer is SERVING (§7).
pub fn grpcHealthServing(answer: *const zoxy.http.h2.Answer) bool {
    assert(answer.body.len == zoxy.http.h2.grpc_serving.body.len);
    return std.mem.eql(u8, answer.body, zoxy.http.h2.grpc_serving.body);
}

/// §7's gRPC check, judged against the origin that answered it. The L4
/// cluster's probes share these counters, so only a seed that checks the
/// http cluster alone can tell its verdicts apart. On a NOT_SERVING seed
/// every call the origin answered was a failed probe — but for one per
/// endpoint the drain may have cut before the prober read it; a skipped
/// probe opened no stream, so it answers for nothing — and on a clean
/// SERVING one none failed.
fn verifyGrpcHealth(harness: *const Harness) !void {
    const answer = &(harness.grpc_health orelse return);
    if (harness.clusters[l4_cluster_index].check != null) return;
    assert(std.mem.eql(u8, harness.clusters[http_cluster_index].name, http_cluster_name));
    const counters = &harness.server.counters;
    const failed = counters.get("health_probes_failed");
    const answered = harness.h2_origin.health_answered;
    if (!grpcHealthServing(answer)) {
        if (answered > failed + harness.endpoints_http_count) return error.GrpcHealthNotServingPassed;
        return;
    }
    if (harness.clean and failed != 0) return error.GrpcHealthServingFailed;
}

/// #481: what the L4 cluster serves, when it follows a name and the
/// datagram adversary flips no octet, is never more than the nameservers
/// could make it: the origin and the next host in address order, an
/// answer cut to two, and never an address a reply under the wrong ID
/// named. A flipped octet is a reply plain DNS has no way to refuse — an
/// address changed in flight (seed 13653), or a second query's answer let
/// through (39735) — so a corrupting seed's set is bounded by the
/// cluster's slots alone, which the endpoint table holds it to.
fn verifyDnsSet(harness: *const Harness) !void {
    if (!harness.dns_l4) return;
    const cluster = &harness.server.config.clusters[l4_cluster_index];
    assert(std.mem.eql(u8, cluster.name, l4_cluster_name));
    const slots = cluster.slots orelse return error.DnsClusterWithoutSlots;
    const intact = harness.io.adversary.udp_corrupt_percent == 0;
    var live: u32 = 0;
    for (slots.states, slots.addresses) |state, *address| {
        if (state != .live) continue;
        live += 1;
        // A reply's address is an IP whatever was flipped in it.
        if (address.* == .unix) return error.DnsSetWrong;
        if (!intact) continue;
        const ip = switch (address.*) {
            .ip => |*ip| ip,
            .unix => return error.DnsSetWrong,
        };
        // Never the address a reply under the wrong ID named, nor the host
        // the cut left out: only the first two in address order.
        if (ip.eql(&zoxy.testing.nameserver_stray_address)) return error.DnsSetWrong;
        const allowed = for (dns_origin_moved[0..2]) |*wanted| {
            if (ip.eql(wanted)) break true;
        } else false;
        if (!allowed) return error.DnsSetWrong;
    }
    if (intact and live > 2) return error.DnsSetWrong;
    assert(live <= slots.states.len);
}

/// #304: every refusal the client CA made was owed — the counter never
/// passes the slots the verdict found owed one — and on a clean seed,
/// where every refused client reaches its certificate step, it is exactly
/// that many. A chain refused by a bare teardown is told by nothing else.
fn verifyClientRefusalCount(harness: *const Harness) !void {
    const refused = harness.server.counters.get("tls_client_cert_refused");
    if (harness.tls_client_verify == null) assert(refused == 0);
    if (refused > harness.tls_client_refusals) return error.TlsClientRefusalsMiscounted;
    if (harness.clean and refused != harness.tls_client_refusals) return error.TlsClientRefusalsMiscounted;
}

/// #297: a handshake that was shown a leaf was shown the one its name
/// chooses, octet for octet. A resumed session is shown none.
fn verifyTlsCertificate(harness: *Harness, client: *const TlsClient, index: usize) !void {
    assert(index < tls_client_slots);
    const shown = client.serverPublicKey() orelse return;
    const offer = harness.tls_scheme_offers[index];
    // An offer nothing the name reaches can sign under is refused before
    // any Certificate goes out (#411).
    const choice = expectedChoice(harness.tls_sni, harness.tls_names[index], offer) orelse
        return error.TlsShownRefusedOffer;
    try harness.verifyShown(shown, choice);
}

/// #297 over QUIC: an HTTP/3 client shown a leaf was shown the one its
/// name chooses. It offers every scheme, so it is never refused.
fn verifyH3Certificate(harness: *Harness, client: *const H3Client, index: usize) !void {
    assert(index < h3_clients_max);
    const shown = client.serverPublicKey() orelse return;
    const choice = expectedChoice(harness.tls_sni, harness.h3_names[index], .all).?;
    try harness.verifyShown(shown, choice);
}

/// #411's verdict for one terminating client whose offer nothing the name
/// reaches can sign under: refused in the handshake — a bare teardown,
/// counted as a failed one — unless it resumed, which signs nothing and
/// so is judged as any session. True when it was refused, and so fully
/// judged here.
fn verifyTlsSchemes(harness: *Harness, client: *const TlsClient, index: usize, back: []const u8) !bool {
    if (!harness.schemeRefusable(index)) return false;
    if (client.handshake_done) {
        assert(client.serverPublicKey() == null); // `verifyTlsCertificate` ran first.
        return false;
    }
    if (back.len != 0) return error.TlsSchemeRefusalServed;
    harness.noteSchemeRefusal(client);
    return true;
}

/// A refused slot whose hello went out whole is owed one failed handshake
/// (#411), which the census then holds against nothing. One the adversary
/// ended before that never reached a handshake to fail.
fn noteSchemeRefusal(harness: *Harness, client: *const TlsClient) void {
    assert(!client.handshake_done);
    if (!client.helloSent()) return;
    harness.tls_scheme_refusals += 1;
    assert(harness.tls_scheme_refusals <= tls_client_slots);
}

/// What a terminated session owes (§4).
///
/// Prefix-legality holds on every seed: whatever came back must be the
/// start of what went out, so a session that decrypted another's bytes or
/// corrupted its own fails wherever it diverged. Exactness is demanded of
/// the sessions that *said* they were done — the client sends its
/// close_notify only once the whole echo is back, so `close_sent` is its
/// own statement that it got everything, and a client that then holds
/// fewer bytes than it sent is a contradiction.
///
/// A proxied session's responses go through the plaintext population's
/// own oracle (#215), which is the point: the argument for terminating
/// in-process is that TLS is a phase ahead of the protocol and not a
/// protocol of its own — the same render, the same filters, the same
/// stamps — and an unexamined response is exactly what leaves that claim
/// untested. It was untested: the #178 sticky stamp shipped 0.2.0
/// omitting `Secure` on terminated connections and `zig build ci` passed
/// identically either side, because all this asked was that the bytes
/// started with "HTTP/1.1 ".
///
/// Not conditioned on `clean`, deliberately, and that is where this stops
/// short of the plaintext oracle. A TLS session costs several more
/// virtual round trips than a plaintext one, so it can legitimately meet
/// the scenario's end mid-exchange on a seed where every plaintext client
/// finished — that is the schedule being short, not the proxy being
/// wrong, and an oracle demanding the golden *count* would fail honest
/// runs. What is demanded is everything that does not depend on how far
/// the schedule got: every complete response parses, carries an allowed
/// status, a canonical body, the #175 stamp its render owes and the #178
/// stamp its cluster owes, and no surplus response beyond the pair.
///
/// Mutation-checked rather than assumed, both directions:
///
///   - Restoring the pre-#125 stamp — no `Secure` on a terminated
///     connection, with the assert that shipped beside it — fails seeds
///     61, 129, 176, 295 and 501 of the first 512. That is the 0.2.0 bug,
///     and this oracle is what would have caught it.
///   - Taking the response filters back off the tls listener fails ~10%
///     of the first 512 on `ResponseEditMissing`, which is how the
///     listener's own filter chain is held to running at all.
///
/// A violation surfaces under the plaintext oracle's own error name.
/// Which population raised it is not in the name, and does not need to
/// be: the plaintext clients verify first, so an error arriving from here
/// is one their transcripts did not have.
fn verifyTlsSessions(harness: *Harness) !void {
    if (harness.tls_clients == 0) return;
    assert(harness.tls_clients_live <= harness.tls_clients_storage.len);
    var closed_count: u8 = 0;
    var refusals: TlsAlpnRefusals = .{};
    for (harness.tls_clients_storage[0..harness.tls_clients_live], 0..) |*client, index| {
        if (try harness.verifyTlsSlot(client, index, &refusals)) closed_count += 1;
    }
    // A session that closed in protocol necessarily completed its
    // handshake, so the counter cannot read lower than that — which is
    // what catches a run that quietly failed handshakes and still
    // satisfied the byte comparison above on empty echoes.
    if (harness.server.counters.get("tls_handshakes_completed") < closed_count) {
        return error.TlsHandshakesDiverged;
    }
    // The counter between what clients heard and what could have been
    // said. Not an equality, because the adversary can end a refused
    // client's socket before the alert lands, and it can end one before
    // its hello reached the server at all.
    const refused = harness.server.counters.get("tls_alpn_refused");
    if (refused < refusals.heard) return error.TlsAlpnRefusalsDiverged;
    if (refused > refusals.possible) return error.TlsAlpnRefusalsDiverged;
    // #411: on a clean seed every hello reaches the listener, so each slot
    // refused for its offer is one failed handshake the counter holds.
    const failed = harness.server.counters.get("tls_handshake_failed");
    if (harness.clean and failed < harness.tls_scheme_refusals) return error.TlsSchemeRefusalsDiverged;
}

/// One terminating client's verdict, for `verifyTlsSessions`: true when
/// the session closed having said it got everything — a proxied one that
/// heard a response, a relayed one that sent its close_notify — which
/// the handshake counter must then account for.
fn verifyTlsSlot(harness: *Harness, client: *const TlsClient, index: usize, refusals: *TlsAlpnRefusals) !bool {
    assert(index < harness.tls_clients_live);
    try harness.verifyTlsCertificate(client, index);
    const back = client.app_received[0..client.app_received_len];
    if (try harness.verifyTlsAlpn(client, index, back, refusals)) {
        // Refusable on both counts, a slot is refused for its offer:
        // zssl picks a scheme before it reads ALPN. Unless it resumed,
        // which signs nothing, and so heard ALPN's alert instead.
        if (!client.refusedForAlpn() and harness.schemeRefusable(index)) harness.noteSchemeRefusal(client);
        return false;
    }
    if (try harness.verifyTlsSchemes(client, index, back)) return false;
    if (try harness.verifyClientCertificate(client, index, back)) return false;
    if (harness.slotSpeaksH2(index)) return harness.verifyTlsH2(client, index, back);
    if (harness.tls_protocol == .http) {
        // What this slot drew, and the same pairing rule
        // `startTlsClient` sent it under: a `routed_canonical` script
        // took a follow-up GET, so its transcript is the pair's;
        // anything else sent one request and owes its own script's
        // transcript exactly.
        const drawn = l7.scripts.spec(harness.tls_scripts[index]);
        const entry = if (drawn.routed_canonical)
            l7.scripts.terminating_pair
        else
            drawn;
        // The spec the walk judges by describes what this session was
        // asked to send, so what went out cannot exceed it — the check
        // that catches the two drifting apart, since a wider send
        // would be judged against a transcript that never mentions it.
        assert(client.requestsSent() <= entry.payloadsSent());
        const walk = HttpClient.walkResponses(
            back,
            entry,
            .{ .sticky = harness.sticky_http, .terminated = true, .interim_owed = harness.interimOwed() },
        );
        if (walk.violation) |violation| return violation;
        // #204: never more answers than questions. The framing rule
        // the client ends its exchanges on is what lets it count them
        // at all, and a count that ran ahead of what it asked for
        // would mean the transform delivered a response this session
        // never earned — another connection's, or one duplicated
        // across the head source's turnaround. Sound on every seed,
        // since a short schedule can only leave the count *behind*.
        // Kept beside the walk rather than folded into it: the walk
        // bounds responses by the transcript, this bounds them by
        // what this session actually sent.
        if (client.responsesReceived() > client.requestsSent()) {
            return error.TlsResponseCountDiverged;
        }
        // Response bytes, not `handshake_done`: a client believes it
        // is connected once it has processed the server's flight,
        // which is one step before the server has seen its Finished —
        // so the client's own view can legitimately lead the server's
        // counter. A relayed response cannot.
        return back.len >= 1;
    }
    const sent = harness.tls_tokens[index][0..tls_token_bytes];
    if (back.len > sent.len) return error.TlsEchoOverrun;
    if (!std.mem.eql(u8, sent[0..back.len], back)) return error.TlsEchoCorrupted;
    if (!client.close_sent) return false;
    if (back.len != sent.len) return error.TlsEchoTruncated;
    return true;
}

const TlsAlpnRefusals = struct {
    /// Clients whose offer this listener could not meet.
    possible: u8 = 0,
    /// Those whose `no_application_protocol` alert actually arrived.
    heard: u8 = 0,
};

/// #271's verdict for one terminating client, answering whether that
/// client was one the listener refuses — in which case it is fully judged
/// here and the caller skips it, since a refused session has no exchange
/// for the walk below to read.
fn verifyTlsAlpn(
    harness: *const Harness,
    client: *const TlsClient,
    index: usize,
    back: []const u8,
    refusals: *TlsAlpnRefusals,
) !bool {
    assert(index < harness.tls_alpn_offers.len);
    const offer = harness.tls_alpn_offers[index];
    if (harness.slotSpeaksH2(index) and !harness.clean) {
        // Served HTTP/2 when a session is free, and otherwise offered the
        // list less `h2` (`alpn_fallback`, #275), which an `h2`-only offer
        // cannot meet. Possible whether or not the alert landed: the
        // adversary can cut the socket between the refusal and its alert.
        refusals.possible += 1;
        if (client.refusedForAlpn()) {
            refusals.heard += 1;
            if (back.len != 0 or client.handshake_done) return error.TlsAlpnRefusalServed;
            return true;
        }
    }
    // A clean seed has a session for every `h2` slot, so it is never
    // refused there: the check below fails it as any wrong refusal.
    // Refused unless the listener speaks HTTP/2 too, which serves it.
    const refusable = harness.tls_protocol == .http and offer == .h2_only and !harness.tls_h2;
    if (refusable) {
        refusals.possible += 1;
        if (client.refusedForAlpn()) refusals.heard += 1;
        // Refused in the handshake, so nothing may have been served: a
        // byte back, or a session up, would mean the client was handed
        // the HTTP/1.1 it never asked for — the gap #271 closes.
        if (back.len != 0) return error.TlsAlpnRefusalServed;
        if (client.handshake_done) return error.TlsAlpnRefusalServed;
        return true;
    }
    // Every other offer is one the listener can meet, so a refusal here
    // would be the server turning away a client it speaks for.
    if (client.refusedForAlpn()) return error.TlsAlpnRefusedWrongly;
    if (client.handshake_done) {
        // And what it met it with is the listener's to decide: HTTP/1.1
        // on an `http` terminator to any client that offered it, and
        // nothing from an `l4` one, which names no protocol.
        const expected: ?[]const u8 = switch (harness.tls_protocol) {
            .http => if (offer == .none) null else if (harness.slotSpeaksH2(index)) "h2" else "http/1.1",
            .l4 => null,
        };
        const selected = client.alpnSelected();
        if ((expected == null) != (selected == null)) return error.TlsAlpnSelectionDiverged;
        if (expected) |name| {
            if (!std.mem.eql(u8, name, selected.?)) return error.TlsAlpnSelectionDiverged;
        }
    }
    return false;
}

/// #178, every seed: the sticky verdicts move only when the cookie
/// cluster was drawn, and then at least once per completed forwarded
/// response — every `l7_responses` increment passed through the render
/// commit that credits exactly one verdict. Not an equality: the credit
/// lands at the render commit and `l7_responses` at the exchange's
/// finish, so an adversary cutting between them legally leaves a
/// credited verdict with no finished response. The exact-bytes demand
/// lives in the client's per-response stamp oracle; this holds the
/// *counters* to the responses they annotate.
fn verifyStickyCounters(harness: *const Harness) !void {
    const counters = &harness.server.counters;
    const total = counters.get("l7_sticky_followed") +
        counters.get("l7_sticky_assigned") +
        counters.get("l7_sticky_repicked");
    if (!harness.sticky_http) {
        if (total != 0) return error.StickyCountersDiverged;
        return;
    }
    if (total < counters.get("l7_responses")) return error.StickyCountersDiverged;
}

/// #142 send, every seed: whatever identity the origin heard must be one
/// some L4 client *was* — the announced-in address where the client
/// carried one through the require listener, the observed peer
/// otherwise. Inverted membership deliberately: origin conns whose drawn
/// mode never parses (mute, frozen, reset) record nothing, and a cut
/// header lands as EOF, so demanding every client be heard would fail
/// legal schedules — but an identity heard that no client was is always
/// a bug. Identities are per-client distinct (announced 203.0.113.N,
/// synthetic ports climb), so a match is attribution, and a parsed
/// header must always announce: zoxy's writers have no LOCAL/UNKNOWN
/// arm. The completeness direction lives in the directed tests, where
/// the origin's mode is pinned to echo.
fn verifyUpstreamIdentities(harness: *const Harness) !void {
    if (harness.proxy_protocol_send_l4 == null) {
        assert(!harness.origin.expect_proxy_header);
        return;
    }
    for (harness.origin.conns[0..harness.origin.conns_count]) |*conn| {
        if (!conn.header_done) continue;
        const announced = conn.announced orelse
            return error.UpstreamHeaderAnnouncedNothing;
        var matched = false;
        var index: u8 = 0;
        while (index < harness.l4_count) : (index += 1) {
            const expected: std.Io.net.IpAddress =
                if (harness.l4_announced_len[index] > 0)
                    harness.l4_announced_address[index]
                else
                    harness.clients[index].observed_address orelse continue;
            if (expected.eql(&announced)) matched = true;
        }
        if (!matched) return error.UpstreamHeardUnknownIdentity;
    }
}

/// The §8 access log's invariants (§9). The sink is a virtual file the
/// harness can read back, so what an operator would have seen is checkable
/// rather than merely believed: the bytes are whole lines, there are
/// exactly as many of them as the counter claims, each is shaped like the
/// documented record, and — when nothing was dropped — every outcome the
/// data path counted has a line to go with it.
///
/// Structural rather than a full JSON parse: `parseFromSlice` allocates,
/// and the simulator does not. The escaping that a parse would catch is
/// pinned by `access_log.zig`'s own tests, against inputs far more hostile
/// than the scripts here send.
fn verifyAccessLog(harness: *Harness) !void {
    const counters = &harness.server.counters;
    const sink = harness.io.sinkBytes();
    if (harness.io.sink_overflow_bytes != 0) return error.AccessLogSinkOverflowed;
    // The sink never fails in the sweep, so every accepted line must have
    // reached it; a failure here would silently weaken every check below.
    if (counters.get("access_log_write_failed") != 0) return error.AccessLogWriteFailed;

    if (harness.config.access_log_sink == null) {
        // Off means off: no bytes, and no counter moved (§5).
        if (sink.len != 0) return error.AccessLogWroteWhileOff;
        if (counters.get("access_log_lines") != 0) return error.AccessLogCountedWhileOff;
        if (counters.get("access_log_dropped") != 0) return error.AccessLogCountedWhileOff;
        return;
    }

    // The drain does not stop the loop until the sink is quiet (§8), so
    // the last byte written is the last byte of a line — never half of one.
    if (sink.len != 0 and sink[sink.len - 1] != '\n') return error.AccessLogTruncatedLine;
    const tally = try tallyAccessLog(sink);
    if (tally.total != counters.get("access_log_lines")) {
        return error.AccessLogLineCountDiverged;
    }

    // A dropped line would make the equality below false for a reason
    // that has nothing to do with the counter list it exists to pin, so
    // the real condition fails first and under its own name. The rung is
    // out of a scenario's reach (see the §9 census's `uncovered` entry),
    // and the census proves that across the range — but only once the
    // range finishes, which is too late to explain a single seed.
    if (counters.get("access_log_dropped") != 0) return error.AccessLogDroppedInSweep;

    // #233: an absolute-form request line's authority overrides the Host
    // beside it, and what the log records is the name the request
    // *routed* on. So the overridden spelling must never reach a line —
    // the same check the origin makes on what it was forwarded, made
    // here on what the operator is told. Only one script can produce
    // these bytes, which is what makes a scan of the whole sink exact.
    if (std.mem.indexOf(u8, sink, l7.canon.overridden_host) != null) {
        return error.AccessLogHostNotOverridden;
    }

    // Every HTTP line is either an outcome the data path counted or an
    // abort — an equality, and the reason this file no longer asks
    // whether the log wrote *enough* lines. The `>=` it replaces was
    // satisfied by writing too many, which is precisely how #129's
    // phantom line per keep-alive connection cleared 4096 seeds.
    //
    // It also pins `l7OutcomeTotal`'s list: a new answered counter left
    // out of it fails this on the first seed that reaches the rung, which
    // is how `l7_shed_endpoint_inflight` turned out to have been missing
    // since it shipped.
    if (tally.http != l7OutcomeTotal(counters) + tally.http_aborted) {
        return error.AccessLogHttpLinesDiverged;
    }

    // A clean seed answers everything it starts, so an abort is a bug
    // rather than an adversary's work. Not quite by construction: what a
    // clean seed removes is every *cause* of an abort — no resets, no
    // kernel pressure, a well-behaved origin, and no drawn drain
    // (`deriveDrainAt` skips clean seeds) — while the request and
    // lifetime deadlines are still drawn and armed. They do not fire
    // because a well-behaved origin answers within microseconds of
    // virtual time, which is an argument about pacing rather than a
    // guarantee; it held across all 1578 clean runs of the sweep.
    //
    // This is the half with teeth. The equality above counts a phantom
    // abort on both sides and passes; this one refuses it outright, and
    // is what fails on seed 10 when #129's bug is put back.
    //
    // The one abort a clean seed owes is an HTTP/2 flood's (#276): the
    // server ends that client's connection on purpose, and the streams it
    // had open with it. Each is traced as a flood's, so the rule stays
    // exact — every abort a flood's, and any other still a bug.
    //
    // The other is the age cap's (§6) on HTTP/3 (#449). The pacing
    // argument above does not hold for a QUIC handshake: soak #145's seed
    // 563537103 drew a 10 ms cap, and its two connections were ended at
    // it with requests open. Those lines are traced as HTTP/3's, and each
    // is excused only when the cap ended its own client's connection.
    if (harness.clean) {
        const h3_excused = harness.h3AbortsExcused(sink);
        assert(h3_excused <= tally.http_aborted);
        if (tally.http_aborted != tally.http_aborted_flood + h3_excused) {
            return error.AccessLogAbortedOnCleanSeed;
        }
        // And each L4 connection is one line: the clients connect once
        // apiece, clean-seed pools are sized well past the population so
        // none is shed at admission, and an L4 connection stamps its
        // clock on admission rather than on first byte — so even the
        // silent clients (`sim/l4.zig` draws some) owe a line, theirs
        // reporting `bytes_in: 0`.
        // TLS is a phase ahead of the protocol (§4), so a terminated
        // connection logs what it went on to speak: an `l4` terminator
        // adds L4 lines — live, not drawn, since #204's resumer is a
        // second connection — and an `http` one adds exchanges above.
        const terminated_l4: u8 =
            if (harness.tls_protocol == .l4) harness.tls_clients_live else 0;
        if (tally.l4 != harness.l4_count + terminated_l4) {
            return error.AccessLogL4LinesDiverged;
        }
        try harness.verifyAnnouncedClients(sink);
    }
}

/// #142, clean seeds only: a client that announced an address via its
/// PROXY header must be logged *as* that address — the same field the §7
/// hash pick keys on, so this is the sweep's witness that the header is
/// believed, not merely consumed (reverting the one believe-the-header
/// line fails seed 20 here). Adversarial seeds are excluded because a cut
/// mid-header rightly logs the observed peer; that a clean seed's header
/// always completes ahead of any drawn deadline is the same pacing
/// argument the clean-abort check above rests on. The addresses are
/// distinct per client, so presence is attribution.
fn verifyAnnouncedClients(harness: *const Harness, sink: []const u8) !void {
    assert(harness.clean);
    assert(harness.l4_count <= clients_max);
    var l4_index: u8 = 0;
    while (l4_index < harness.l4_count) : (l4_index += 1) {
        const announced_len = harness.l4_announced_len[l4_index];
        if (announced_len == 0) continue;
        var needle_buffer: [announced_bytes_max + 11]u8 = undefined;
        const needle = std.fmt.bufPrint(
            &needle_buffer,
            "\"client\":\"{s}\"",
            .{harness.l4_announced[l4_index][0..announced_len]},
        ) catch unreachable; // The key wrapper is exactly 11 bytes.
        if (std.mem.indexOf(u8, sink, needle) == null) {
            return error.AccessLogAnnouncedClientMissing;
        }
    }
}

/// What the sink's lines are, counted by kind and outcome. Every line is
/// shape-checked on the way past, so a malformed one fails here rather
/// than being silently tallied.
const LineTally = struct {
    total: u64 = 0,
    http: u64 = 0,
    l4: u64 = 0,
    http_aborted: u64 = 0,
    /// Those of them an HTTP/2 flood's request asked for.
    http_aborted_flood: u64 = 0,
};

/// The aborted HTTP/3 lines the age cap (§6) accounts for, client by
/// client: each from a client whose connection the server closed
/// gracefully, seen no sooner than the cap past that client's start
/// (`H3Client.verify` reads the same), and named by its line's own
/// client address — the loopback port its socket bound.
fn h3AbortsExcused(harness: *const Harness, sink: []const u8) u64 {
    assert(harness.h3_count <= h3_clients_max);
    const max_lifetime_ns = @as(u64, harness.server.config.max_lifetime_ms) * std.time.ns_per_ms;
    if (max_lifetime_ns == 0) return 0;
    var excused: u64 = 0;
    for (harness.h3_clients[0..harness.h3_count]) |*client| {
        if (!client.began) continue;
        if (!client.transport.peerClosedGracefully(max_lifetime_ns)) continue;
        var needle_buffer: [40]u8 = undefined;
        const needle = std.fmt.bufPrint(&needle_buffer, "\"client\":\"127.0.0.1:{d}\"", .{
            client.transport.local_port,
        }) catch unreachable;
        var lines = std.mem.splitScalar(u8, sink, '\n');
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line, "\"outcome\":\"aborted\"") == null) continue;
            if (std.mem.indexOf(u8, line, l7.canon.log_request_h3_value) == null) continue;
            if (std.mem.indexOf(u8, line, needle) != null) excused += 1;
        }
    }
    assert(excused <= sink.len);
    return excused;
}

fn tallyAccessLog(sink: []const u8) !LineTally {
    var tally: LineTally = .{};
    var lines = std.mem.splitScalar(u8, sink, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue; // The tail after the final newline.
        tally.total += 1;
        try verifyAccessLogLine(line);
        if (std.mem.indexOf(u8, line, "\"kind\":\"http\"") == null) {
            tally.l4 += 1;
            continue;
        }
        tally.http += 1;
        // A tunnel's line is already explained by `tunnels_established`
        // (#180), so it must not also be counted as an unexplained
        // abort. Its outcome legitimately goes both ways — `closed` when
        // both halves said goodbye, `aborted` when a drain or a peer cut
        // it — because after `101` this connection ends the way an L4
        // relay ends, not the way an exchange does. Never `ok`: only
        // `finishExchange` sets that, and a tunnel never returns there.
        // The status is what identifies it: `101` is the one status no
        // ordinary exchange can carry, since the proxy answers it only
        // for a tunnel that its client provably received.
        if (std.mem.indexOf(u8, line, "\"status\":101") != null) {
            continue;
        }
        if (std.mem.indexOf(u8, line, "\"outcome\":\"aborted\"") != null) {
            tally.http_aborted += 1;
            if (std.mem.indexOf(u8, line, l7.canon.log_request_flood_value) != null) tally.http_aborted_flood += 1;
        }
    }
    assert(tally.http + tally.l4 == tally.total);
    assert(tally.http_aborted <= tally.http);
    assert(tally.http_aborted_flood <= tally.http_aborted);
    return tally;
}

/// Every L7 outcome that answers a client, summed. Each one runs through
/// `respond` or `finishExchange`, and both emit a line.
///
/// Not `conn_policy_rejected` (#425), though a refused http connection
/// logs an http line: the counter is shared with l4 refusals, and no sim
/// http connection is refused — its peers are TEST-NET-2, the policy
/// refuses TEST-NET-1, and only l4 listeners take a PROXY header. A sweep
/// that refuses one on an http listener needs its own term here.
fn l7OutcomeTotal(counters: *const zoxy.counters.Counters) u64 {
    const answered = [_][]const u8{
        "l7_responses",
        "l7_bad_request",
        "l7_uri_too_long",
        "l7_headers_too_large",
        // The #125 sibling: a terminated connection whose head fit and
        // whose body did not. Answered like the two above, so it belongs
        // in the same sum — added while it is free rather than on the
        // first seed that reaches it.
        "l7_body_too_large",
        // The #236 cap's answered half. Its sibling
        // `l7_body_cut_mid_stream` is deliberately absent: that one tears
        // the exchange down without a status, so its line is an abort and
        // counting it here would explain the same line twice.
        "l7_body_over_limit",
        "l7_not_implemented",
        "l7_no_route",
        "l7_filtered",
        "l7_policy_rejected",
        // A consult that failed a type closed, and a request whose own
        // deadline ran out under its consult (#437): both answered.
        "l7_policy_consult_refused",
        "l7_policy_consult_expired",
        "l7_redirected",
        "l7_responded",
        // A build's handler answered (#434), or its route refused the
        // body or the answer: each a line like any answered exchange.
        "l7_handled",
        "l7_handler_body_too_large",
        "l7_handler_answer_refused",
        // The #240 final-recipient answer: served, so it owes a line like
        // every other answered exchange.
        "l7_max_forwards_exhausted",
        "l7_shed_relay_buffers",
        "l7_shed_tunnels",
        // A tunnel is an *answered* exchange like any other here (#180):
        // the client asked for an upgrade and got its `101`. It is the
        // one member that reaches neither `respond` nor `finishExchange`
        // — its line is written at close by the ordinary teardown path —
        // which is why the sum's own description above names two paths
        // and this needs a third. Leaving it out makes the line
        // unexplained, exactly what this identity caught on the first
        // seed to carry one.
        "tunnels_established",
        "l7_shed_upstream_slots",
        "l7_shed_h2_origin_connections",
        "l7_shed_h2_origin_streams",
        "l7_shed_upstream_tls",
        "l7_shed_endpoint_inflight",
        // #392's cluster-wide cap: a shed answered through `respond`,
        // owing a line like the endpoint cap beside it.
        "l7_shed_total_inflight",
        "l7_bad_gateway",
        "l7_gateway_timeout",
        // A gRPC call's own deadline: the same verdict, answered as gRPC
        // reads one, and owing a line the same way.
        "l7_grpc_deadline_exceeded",
        // The #247 head-read verdict. It answers `408` and so owes a
        // line, exactly like the `504` above it — the difference between
        // them is which side ran out of time, which the status says and
        // this sum does not care about. Before #247 the same reap wrote
        // an *abort* line and belonged on the other side of the equality.
        "l7_request_timeout",
    };
    var total: u64 = 0;
    inline for (answered) |name| {
        total += counters.get(name);
    }
    return total;
}

/// One line's shape: a JSON object carrying every key the record defines,
/// in the order `renderLine` writes them.
fn verifyAccessLogLine(line: []const u8) !void {
    assert(line.len >= 1);
    if (line[0] != '{') return error.AccessLogLineNotAnObject;
    if (line[line.len - 1] != '}') return error.AccessLogLineNotAnObject;
    const required = [_][]const u8{
        "\"time\":\"",
        "\"kind\":\"",
        "\"outcome\":\"",
        "\"client\":\"",
        "\"duration_us\":",
        "\"bytes_in\":",
        "\"bytes_out\":",
        "\"cluster\":",
        "\"upstream\":",
    };
    var searched: usize = 0;
    for (required) |key| {
        // Searched forward from the previous key, so the order is checked
        // too: a renderer that emitted the right keys in a shuffled order
        // would still break a consumer reading them positionally.
        const at = std.mem.indexOfPos(u8, line, searched, key) orelse
            return error.AccessLogLineMissingKey;
        searched = at + key.len;
    }
    // An HTTP line carries the request fields; an L4 line must not, or a
    // consumer keying off `kind` finds a status for a connection that
    // never had one.
    const is_http = std.mem.indexOf(u8, line, "\"kind\":\"http\"") != null;
    const has_status = std.mem.indexOf(u8, line, "\"status\":") != null;
    if (is_http != has_status) return error.AccessLogLineWrongShape;
    try verifyLoggedHeaders(line, is_http);
}

/// The #140 objects (§9). Every seed names one header each way, so an
/// http line must carry both objects and an l4 line neither — a
/// connection has no head to have read one from. Within them, the only
/// value that may ever appear is the one the scripts and the origin
/// send: a capture that truncated or corrupted fails here under every
/// schedule. A capture that went *stale* does not, since every sender
/// shares one value — the directed tests own that one.
fn verifyLoggedHeaders(line: []const u8, is_http: bool) !void {
    const request_key = "\"request_headers\":";
    const response_key = "\"response_headers\":";
    const has_request = std.mem.indexOf(u8, line, request_key) != null;
    const has_response = std.mem.indexOf(u8, line, response_key) != null;
    if (has_request != is_http) return error.AccessLogHeadersWrongShape;
    if (has_response != is_http) return error.AccessLogHeadersWrongShape;
    if (!is_http) return;
    // A flood's requests carry their own trace (#276), and so do HTTP/3's
    // (#449); any other value is a capture gone wrong.
    verifyLoggedValue(line, l7.canon.log_request_header, l7.canon.log_request_value) catch {
        verifyLoggedValue(line, l7.canon.log_request_header, l7.canon.log_request_flood_value) catch {
            try verifyLoggedValue(line, l7.canon.log_request_header, l7.canon.log_request_h3_value);
        };
    };
    try verifyLoggedValue(line, l7.canon.log_response_header, l7.canon.log_response_value);
}

/// One logged name carries the canonical value or does not appear.
fn verifyLoggedValue(line: []const u8, name: []const u8, value: []const u8) !void {
    assert(name.len >= 1);
    assert(name.len <= zoxy.constants.access_log_header_name_bytes_max);
    assert(value.len >= 1);
    assert(value.len <= zoxy.constants.access_log_header_bytes_max);
    // Sized from the caps the loader enforces, so this helper stays
    // sound for any name and value a config could legally hold — the
    // `catch unreachable`s below are what rest on that.
    var needle_buffer: [zoxy.constants.access_log_header_name_bytes_max + 4]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buffer, "\"{s}\":", .{name}) catch unreachable;
    const at = std.mem.indexOf(u8, line, needle) orelse return;
    var expected_buffer: [
        zoxy.constants.access_log_header_name_bytes_max +
            zoxy.constants.access_log_header_bytes_max + 8
    ]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "\"{s}\":\"{s}\"",
        .{ name, value },
    ) catch unreachable;
    if (!std.mem.startsWith(u8, line[at..], expected)) {
        return error.AccessLogHeaderValueWrong;
    }
}

/// Both clients' ended hook: type-erased because the client files cannot
/// know the harness type.
fn clientEndedHook(context: ?*anyopaque) void {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    harness.clientEnded();
}

/// Per-accept origin behavior, drawn from the harness's scenario PRNG so
/// each proxied connection meets a random misbehavior (echo / RST / mute /
/// frozen) — the §9 adversarial-origin coverage.
fn pickOriginMode(context: ?*anyopaque) zoxy.testing.Mode {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    return harness.scenario_prng.random().enumValue(zoxy.testing.Mode);
}

/// Whether every answer the http cluster's origin gives comes behind an
/// interim `100` (#232): an interim seed's, where that origin is the
/// HTTP/1.1 one (`pickHttpOriginMode`) or the HTTP/2 one (`pickH2Answer`).
/// The HTTPS origin prefixes none.
fn interimOwed(harness: *const Harness) bool {
    assert(harness.http_protocol.http2() == (harness.http_protocol != .http1));
    const prefixes = harness.http_protocol.http2() or !harness.http_tls;
    return harness.interim_http and prefixes;
}

/// Per-accept HTTP-origin misbehavior, drawn like the L4 origin's. Clean
/// seeds pin every connection to the well-behaved sized mode so golden
/// outcomes stay exact.
fn pickHttpOriginMode(context: ?*anyopaque) l7.OriginMode {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    if (harness.clean) {
        return if (harness.interim_http) .interim_then_sized else .sized;
    }
    if (harness.interim_http) return .interim_then_sized;
    return harness.scenario_prng.random().enumValue(l7.OriginMode);
}
