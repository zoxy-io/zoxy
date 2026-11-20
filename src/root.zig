//! zoxy — bullet-proof L4/L7 proxy (see docs/DESIGN.md). This module root
//! re-exports the library surface and references every source file so that
//! `zig build test` compiles and runs all tests.

const std = @import("std");

pub const access_log = @import("access_log.zig");
/// zoxy as a process (#417): the startup sequence, `--check`, and the
/// selection helpers a build's options use. `App(extensions)` is what a
/// binary built on this library calls once its config exists.
pub const app = @import("app.zig");
pub const App = app.App;
pub const balancer = @import("balancer.zig");
/// The §5/§8 startup budget: pool sizes, fd and ring demands, the banner.
/// Generic over the `Runtime` like `Server`, and the reason it is here
/// rather than in an application is §13 — the closed form must price exactly what
/// `Server.init` reserves, so an embedder inherits it instead of copying it.
pub const Budget = @import("budget.zig").Budget;
pub const config = @import("config.zig");
/// What a build states about the proxy it runs (#417): the library's one
/// input, validated and compiled by `config.resolve` — by `App.serve`
/// and `App.check` for a build that runs through them.
pub const Options = @import("Options.zig");
/// zoxy's stock values (#417): what the stock binary's JSON applies where
/// a key is absent, named for a build that wants the same choice.
pub const defaults = @import("defaults.zig");
/// The extension seam (#417): `Runtime` is what every part of the serving
/// path is generic over — the Io backend and the build's extensions —
/// and `Extensions` lists the extension types one build carries.
pub const extension = @import("extension.zig");
pub const Extensions = extension.Extensions;
pub const Runtime = extension.Runtime;
/// zoxy's stock pick policies — round-robin, the power of two choices,
/// rendezvous hashing — on the picker contract (#417): what the balancer
/// runs for `rr`, `p2c` and `hash`, and what a build may select or call
/// like any picker it lists.
pub const pickers = @import("pickers.zig");
pub const constants = @import("constants.zig");
pub const counters = @import("counters.zig");
/// L7 HTTP/1.1 modules (§7). `parser` wraps the vendored hparse behind
/// the trust boundary, `render` writes upstream/downstream heads, and
/// `proxy` is the request-lifecycle state machine over both.
pub const http = struct {
    pub const parser = @import("http/parser.zig");
    pub const render = @import("http/render.zig");
    pub const router = @import("http/router.zig");
    pub const filter = @import("http/filter.zig");
    pub const proxy = @import("http/proxy.zig");
    pub const grpc = @import("http/grpc.zig");
    /// What a client outside `src/http/h2/` needs to read a server's
    /// HTTP/2 field sections (#275), and the per-connection budgets a
    /// client can overrun (#276): the simulator's h2c client, which sends
    /// one past each.
    pub const h2 = struct {
        pub const ResponseReader = @import("http/h2/ResponseReader.zig");
        pub const budgets = struct {
            const Session = @import("http/h2/Session.zig");
            pub const Calm = Session.Calm;
            pub const Unpaid = Session.Unpaid;
            pub const resets_unpaid_max = Session.resets_unpaid_max;
            pub const field_block_frames_max = Session.field_block_frames_max;
        };
    };
};
pub const Io = @import("io/io.zig");
pub const Pool = @import("mem/Pool.zig").Pool;
pub const RelayBuffer = @import("net/relay.zig").RelayBuffer;
pub const UpstreamHeadBuffer = @import("net/upstream.zig").HeadBuffer;
pub const UpstreamPool = @import("net/upstream.zig").UpstreamPool;
pub const Server = @import("Server.zig").Server;
pub const shed = @import("shed.zig");
/// TLS termination (§4). The only files that may name zssl, and so the
/// only place libcrypto is reachable from — lint-enforced.
pub const tls = struct {
    pub const Credentials = @import("tls/Credentials.zig");
    pub const Engine = @import("tls/Engine.zig");
    pub const libcrypto_heap = @import("tls/libcrypto_heap.zig");
    pub const Tickets = @import("tls/Tickets.zig");
    /// A listener's certificates chosen by server name (#297).
    pub const certificate_set = @import("tls/certificate_set.zig");
    /// Chain verification and a leaf's DNS names — `zoxy.App` reads the
    /// names a listener's certificates are chosen by (#297).
    pub const trust = @import("tls/trust.zig");
    pub const TestClient = @import("tls/TestClient.zig").TestClient;
    /// What a client captures from one session to offer on the next. Named
    /// here so a gate can hold one without naming zssl itself (§4).
    pub const SessionTicket = @import("tls/TestClient.zig").SessionTicket;
    /// The throwaway self-signed fixtures (`tls/testdata/README.md`),
    /// re-exported because `@embedFile` cannot escape its module root and
    /// the §9 simulator is its own module. Test material, never a
    /// production surface — the key signs nothing but in-memory
    /// handshakes and is trusted by nothing.
    pub const testdata = struct {
        pub const cert_pem = @embedFile("tls/testdata/cert.pem");
        pub const key_pem = @embedFile("tls/testdata/key.pem");
        /// The CA the origin fixtures chain to (#296), and the one client
        /// certificates are issued under (#304): what the JSON front-end's
        /// tests serve for a config's CA paths.
        pub const origin_ca_pem = @embedFile("tls/testdata/origin-ca.pem");
        pub const client_ca_pem = @embedFile("tls/testdata/client-ca.pem");
        /// The certificate's SAN: a client offering any other name fails
        /// verification for a reason unrelated to what is under test.
        pub const host_name = "spike.zoxy.test";
    };
};
/// Shared test-support harness pieces, factored out so multiple test
/// suites can drive the same origin double instead of growing their own.
pub const testing = struct {
    pub const Origin = @import("testing/origin.zig").Origin;
    pub const Mode = @import("testing/origin.zig").Mode;
    /// Comptime byte repetition, for the simulator's canned wire bytes.
    pub const repeat = @import("testing/bytes.zig").repeat;
    /// A picker that records what it was offered and answers a scripted
    /// slot (#417): the gates' way through the extension seam.
    pub const ScriptedPicker = @import("testing/picker.zig").ScriptedPicker;
    /// A request policy that refuses one path prefix and records what it
    /// evaluated (#417).
    pub const ScriptedPolicy = @import("testing/policy.zig").ScriptedPolicy;
    /// A handler that answers with its path, a flag a `POST` flips, and the
    /// body it read (#434).
    pub const ScriptedHandler = @import("testing/handler.zig").ScriptedHandler;
    /// A health-check kind that sends scripted rounds and expects each
    /// echoed (#436).
    pub const ScriptedProbe = @import("testing/probe.zig").ScriptedProbe;
    /// A connection policy that answers every connection with one
    /// scripted verdict (#425).
    pub const ScriptedConnectionPolicy = @import("testing/connection_policy.zig").ScriptedConnectionPolicy;
    /// A response policy that edits every head it reads with a scripted
    /// list (#424).
    pub const ScriptedResponsePolicy = @import("testing/response_policy.zig").ScriptedResponsePolicy;
    /// A build's own test bed (#417): its options resolved, a server over
    /// the simulator with its extensions, origins on every endpoint, and
    /// HTTP clients to drive — the serving path zoxy's own gates run.
    pub const Bed = @import("testing/bed.zig").Bed;
    /// The §9 zero-allocation gate, over a build's own scenario on a
    /// `Bed`.
    pub const expectNoAllocationAfterStartup = @import("testing/bed.zig").expectNoAllocationAfterStartup;
    /// The simulator a `Bed` runs on, for a test that drives it further.
    pub const SimIo = @import("io/SimIo.zig");
};

test {
    _ = access_log;
    _ = app;
    _ = balancer;
    _ = @import("budget.zig");
    _ = config;
    _ = Options;
    _ = defaults;
    _ = extension;
    _ = @import("extension_metrics.zig");
    _ = @import("extension_answers.zig");
    _ = pickers;
    _ = constants;
    _ = counters;
    _ = http.parser;
    _ = http.render;
    _ = http.router;
    _ = http.filter;
    _ = http.proxy;
    _ = http.grpc;
    _ = @import("http/h2/Session.zig");
    _ = @import("http/h2/StreamTable.zig");
    _ = @import("http/h2/downgrade.zig");
    _ = @import("http/h2/response.zig");
    _ = @import("http/h2/origin.zig");
    _ = @import("http/h2/origin_pool.zig");
    _ = @import("http/h2/session_test.zig");
    _ = @import("http/h2/client_session_test.zig");
    _ = Io;
    _ = Server;
    _ = shed;
    _ = tls.Credentials;
    _ = tls.Engine;
    _ = tls.Tickets;
    _ = @import("tls/alpn.zig");
    _ = @import("tls/trust.zig");
    _ = @import("tls/certificate_set.zig");
    _ = @import("tls/OriginClient.zig");
    _ = @import("tls/engine_test.zig");
    _ = tls.TestClient;
    _ = @import("mem/Pool.zig");
    _ = @import("net/Conn.zig");
    _ = @import("net/proxy_protocol.zig");
    _ = @import("net/client_hello.zig");
    _ = @import("net/sni_router.zig");
    _ = @import("net/relay.zig");
    _ = @import("net/upstream.zig");
    _ = @import("testing/origin.zig");
    _ = @import("testing/bytes.zig");
    _ = @import("testing/picker.zig");
    _ = @import("testing/policy.zig");
    _ = @import("testing/bed.zig");
    _ = @import("net/pump_transform_test.zig");
    _ = @import("io/contract_test.zig");
    _ = @import("io/sim_io_test.zig");
    _ = @import("io/xev_smoke_test.zig");
    _ = @import("server_test.zig");
    _ = @import("http_proxy_test.zig");
    _ = @import("admin_test.zig");
    _ = @import("access_log_test.zig");
    _ = @import("zero_alloc_test.zig");
}
