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
/// The extension seam (#417): `Runtime` is what every part of the serving
/// path is generic over — the Io backend and the build's extensions —
/// and `Extensions` lists the extension types one build carries.
pub const extension = @import("extension.zig");
pub const Extensions = extension.Extensions;
pub const Runtime = extension.Runtime;
pub const config_schema = @import("config_schema.zig");
pub const json_schema = @import("json_schema.zig");
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
};

test {
    _ = access_log;
    _ = app;
    _ = balancer;
    _ = @import("budget.zig");
    _ = config;
    _ = extension;
    _ = config_schema;
    _ = json_schema;
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
