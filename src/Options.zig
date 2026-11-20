//! What a build states about the proxy it runs (#417): the library's one
//! input. A custom build writes these in code; the stock binary's JSON is
//! a front-end that writes them from a file, and nothing past this type
//! knows which happened. `config.resolve` validates them — every refusal
//! the stock loader makes, made of the options alone — and compiles them
//! into the `Config` the server runs.
//!
//! **Explicit by construction.** A field has no default if it decides
//! where traffic goes, when work is refused, or what is reserved:
//! deadlines, policies, caps a listener promises its clients. Optional
//! features default to off. The stock binary's JSON applies zoxy's stock
//! values where its keys are absent; a build writing options in code
//! states its own, or names the stock ones (`zoxy.defaults`).
//!
//! **Bytes, not paths.** Certificates, CA bundles and bodies arrive as
//! bytes, so validating options reads no file: whoever builds them does,
//! from wherever they keep them.
//!
//! **Typed, not spelled.** Where JSON names a policy with a string and a
//! fork with a choice of keys, these carry an enum and a union, so the
//! refusals that only a spelling can earn stay in the JSON front-end.
//!
//! **Named, not indexed.** A route names its cluster as the cluster names
//! itself, and a page its body; resolving refuses a name nothing declares.
//!
//! **Kept, not copied.** The resolved `Config` points into the options'
//! own memory — names, prefixes, bodies, PEM bytes, selections — so
//! whoever builds them keeps that memory for the process's life: static
//! data, or the startup arena.

const std = @import("std");

const config = @import("config.zig");
const extension = @import("extension.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");
const io = @import("io/io.zig");
const alpn = @import("tls/alpn.zig");

/// The sockets the proxy accepts on; at least one.
listeners: []const Listener,
/// The upstream clusters listeners and routes name; at least one.
clusters: []const Cluster,
timeouts: Timeouts,
/// Stated, so leaving the sizing to zoxy is something a build writes
/// down rather than inherits; each member left null is sized by zoxy's
/// own rule for this config.
limits: Limits,
/// The admin listener (§8), or null for none.
admin: ?Admin = null,
/// The access log (§8), or null for none.
access_log: ?AccessLog = null,
/// Named bodies, for error pages and `respond` actions (#159).
bodies: []const Body = &.{},
/// Bodies for statuses zoxy answers itself; a status no page names keeps
/// its empty one.
error_pages: []const ErrorPage = &.{},

/// One listening socket (§4): where it binds, whether it terminates TLS,
/// and what it speaks.
pub const Listener = struct {
    /// An IP literal and port, or an absolute `unix:` socket path.
    bind: io.Address,
    /// A `unix:` socket file's permission bits — no setuid, setgid or
    /// sticky — or null to leave the umask's.
    mode: ?io.FileMode = null,
    /// Terminate TLS on this socket (§4), or null for plaintext.
    tls: ?Tls = null,
    protocol: Protocol,
    /// #425's connection policies, in order, on every connection admitted
    /// here, l4 or http, before a handshake, a peek or a first head; the
    /// first refusal wins.
    connection_policies: []const extension.Selection = &.{},

    /// Tagged by the resolved listener's own protocol, so the two cannot
    /// come to name different sets.
    pub const Protocol = union(config.Config.Listener.Protocol) {
        /// A byte relay.
        l4: L4,
        /// A reverse proxy for HTTP/1.1, and HTTP/2 where offered.
        http: Http,
    };

    pub const Tls = struct {
        /// The certificate chain, PEM.
        cert_pem: []const u8,
        /// Its private key, PEM: ECDSA P-256 or P-384, or RSA of 2048 to
        /// 4096 bits.
        key_pem: []const u8,
        /// What a startup error calls this pair.
        label: []const u8,
        /// The ALPN offer, most preferred first; null offers the
        /// protocol's own — HTTP/1.1 on an http listener, nothing on an
        /// l4 one, which takes no offer.
        alpn: ?[]const Alpn = null,
        /// Mutual TLS (#304), or null to ask no client for a certificate.
        client_ca: ?ClientCa = null,
        /// Further pairs, chosen by the server name a client asks for
        /// (#297); this pair stays the default.
        certificates: []const Certificate = &.{},
    };

    pub const Alpn = alpn.Protocol;
    pub const ClientVerify = config.Config.Listener.ClientVerify;
    pub const Certificate = config.Config.Listener.Certificate;

    pub const ClientCa = struct {
        /// The PEM bundle a client's chain must reach.
        ca_pem: []const u8,
        /// Whether a client without a certificate is refused or let on.
        verify: ClientVerify,
    };

    pub const Http = struct {
        /// Where requests go.
        target: Target,
        /// #417's request policies, in order, after the request is
        /// canonicalized and before the filters; the first reject wins.
        request_policies: []const extension.Selection = &.{},
        /// #424's response policies, in order, on every response head the
        /// listener's routes relay, after the response filters.
        response_policies: []const extension.Selection = &.{},
        /// The §7 request filters, walked top-down.
        request_filters: []const Filter = &.{},
        /// The #175 response filters, walked top-down.
        response_filters: []const ResponseFilter = &.{},
        /// Tell the origin the client's address in `X-Forwarded-For`, or
        /// null to leave the header as it arrived.
        forwarded: ?Forwarded = null,
        /// Protocol upgrades carried as tunnels (#180); none by default.
        upgrades: Upgrades = .{},
        /// The cap on one request body (#236); 0 accepts any size.
        max_body_bytes: u64,
        /// Requests one client connection may serve before the response
        /// that announces its close (#237); 0 is unlimited.
        keepalive_requests: u32,
        /// Say why zoxy refused a request, in an RFC 9209 Proxy-Status
        /// field (#300). It reveals internal limits to clients.
        proxy_status: bool = false,
        /// Also take HTTP/2 by prior knowledge on a plaintext socket
        /// (#275); a TLS listener offers `h2` in its ALPN instead.
        h2c: bool = false,
    };

    pub const Forwarded = config.Config.Listener.Forwarded;
    pub const Upgrades = config.Config.Listener.Upgrades;

    pub const Target = union(enum) {
        /// Every request to one cluster, by name.
        cluster: []const u8,
        /// A route table, at least one route. Resolving sorts it most
        /// specific first — host, then header, then prefix length — and
        /// routes equally specific keep the order given.
        routes: []const Route,
    };

    /// One §7 route: every stated key must hold for a request to take it.
    pub const Route = struct {
        /// A canonical host, or null for any.
        host: ?[]const u8 = null,
        /// A canonical, segment-aware path prefix.
        prefix: []const u8,
        /// A header the request must carry (#302), or null.
        header: ?RouteHeader = null,
        /// The cluster's name; empty on a handler route, and required on
        /// every other.
        cluster: []const u8 = "",
        /// A build's handler that answers the route's requests itself
        /// (#434), selected with `App.handler`, in place of a cluster.
        handler: ?extension.Selection = null,
        /// #417's route-phase request policies, run once the route is
        /// chosen and before any resource is taken; the first reject wins.
        request_policies: []const extension.Selection = &.{},
        /// #424's response policies on this route, in order, on every
        /// response head it relays — before the response filters.
        response_policies: []const extension.Selection = &.{},
        /// A name a build's request policy routes by (#430), unique on its
        /// listener, or null. Set in code alone: the JSON front-end has no
        /// key for it, so a stock config's routes are unnamed.
        name: ?[]const u8 = null,
    };

    pub const RouteHeader = struct {
        name: []const u8,
        predicate: Predicate,

        pub const Predicate = union(enum) {
            present,
            equals: []const u8,
        };
    };

    /// One §7 request rule: a match, and what to do when it holds.
    pub const Filter = struct {
        match: Match = .{},
        /// At least one.
        actions: []const Action,
    };

    /// Every stated key must hold; the empty match holds for every
    /// request.
    pub const Match = struct {
        /// The methods it holds for, at least one, or null for any.
        methods: ?std.EnumSet(Method) = null,
        /// A canonical host.
        host: ?[]const u8 = null,
        /// A canonical, segment-aware path prefix.
        path_prefix: ?[]const u8 = null,
        headers: []const HeaderMatch = &.{},
        /// The client addresses it holds for (#177); none is any client.
        clients: []const Cidr = &.{},
    };

    pub const Method = parser.Method;
    /// An address and a prefix length with no host bits past it; an IPv6
    /// prefix is at most 64 bits, a client's identity there.
    pub const Cidr = filter.Cidr;

    pub const HeaderMatch = struct {
        /// Matched without regard to case.
        name: []const u8,
        predicate: Predicate,

        pub const Predicate = union(enum) {
            present,
            equals: []const u8,
            /// A non-empty substring.
            contains: []const u8,
        };
    };

    pub const Action = union(enum) {
        /// Refuse with a status from the static reject set.
        reject: u16,
        redirect: filter.Redirect,
        /// Answer from a named body (#159).
        respond: Respond,
        /// Stop walking the filters, and route (#331).
        allow,
        header_set: filter.HeaderEdit,
        header_add: filter.HeaderEdit,
        header_remove: []const u8,
        rewrite_prefix: filter.Rewrite,
    };

    pub const Respond = struct {
        /// A status zoxy can send a page for.
        status: u16,
        /// The name of one of the build's bodies.
        body: []const u8,
    };

    /// One #175 response rule: a match over the origin's response, and the
    /// header edits to make when it holds.
    pub const ResponseFilter = struct {
        match: ResponseMatch = .{},
        /// At least one.
        actions: []const ResponseAction,
    };

    pub const ResponseMatch = struct {
        /// Statuses in 100..599 it holds for; none is any status.
        statuses: []const u16 = &.{},
        status_class: ?filter.StatusClass = null,
        headers: []const HeaderMatch = &.{},
    };

    pub const ResponseAction = union(enum) {
        header_set: filter.HeaderEdit,
        header_add: filter.HeaderEdit,
        header_remove: []const u8,
    };

    pub const L4 = struct {
        /// Where connections go.
        target: L4Target,
        /// Require a PROXY protocol header on every connection (#142), or
        /// null to read none.
        proxy_protocol: ?ProxyProtocol = null,
    };

    pub const ProxyProtocol = config.Config.Listener.ProxyProtocol;

    pub const L4Target = union(enum) {
        /// Every connection to one cluster, by name.
        cluster: []const u8,
        /// A table chosen by the ClientHello's server name (#298), at
        /// least one route; plaintext listeners only, since a terminating
        /// one has consumed the hello it would read.
        routes: []const SniRoute,
    };

    pub const SniRoute = struct {
        /// A canonical DNS name, or null for every other name and none.
        sni: ?[]const u8 = null,
        /// The cluster's name.
        cluster: []const u8,
        /// #425's connection policies on this route, in order, once the
        /// hello is read and before the dial; the first refusal wins.
        connection_policies: []const extension.Selection = &.{},
    };
};

/// One upstream cluster (§7): a named set of endpoints and how traffic
/// reaches them. Routes and listeners name it.
pub const Cluster = struct {
    /// Unique across the build, at most `cluster_name_bytes_max` bytes.
    name: []const u8,
    /// At least one.
    endpoints: []const Endpoint,
    /// How an endpoint is chosen for each connection or request.
    pick: Pick,
    /// What the origins speak. HTTP/2 to the origins is a feature, so
    /// HTTP/1.1 is the default.
    protocol: Protocol = .http1,
    /// Active health checks (§7), or null for none.
    check: ?Check = null,
    /// Ejection on the failures traffic sees (#230), or null for none.
    passive_ejection: ?PassiveEjection = null,
    /// Below this share of healthy endpoints, pick as if all were
    /// healthy (#390); null fails open only once none is. Needs a health
    /// signal: a check, passive ejection, or both.
    panic_threshold_percent: ?u8 = null,
    /// Requests one endpoint may hold at once (§8), or null for no cap.
    max_inflight: ?u32 = null,
    /// Requests the whole cluster may hold at once (#392), or null.
    max_total_inflight: ?u32 = null,
    /// Ramp a restored endpoint's share over this window (#391), or
    /// null for none. Needs `max_inflight` and a health signal.
    slow_start_ms: ?u32 = null,
    retries: Retries = .{},
    /// Send a PROXY protocol header to the origins (#142), or null.
    proxy_protocol_send: ?ProxyProtocolSend = null,
    /// TLS to the origins (#296), or null for plaintext.
    tls: ?Tls = null,

    pub const Protocol = config.Config.Cluster.Protocol;
    pub const ProxyProtocolSend = config.Config.Cluster.ProxyProtocolSend;
    /// What `hash` keys on (#178): the client address, or a named
    /// header or cookie.
    pub const HashKey = config.Config.Cluster.HashKey;

    pub const Endpoint = struct {
        /// An IP literal with a non-zero port, or an absolute `unix:`
        /// socket path.
        address: io.Address,
        /// Its share of picks against its siblings (#174); 0 drains it.
        weight: u16 = 1,
        /// Its standby tier, 0 the primary (#396).
        priority: u8 = 0,
    };

    pub const Pick = union(enum) {
        rr,
        p2c,
        hash: HashKey,
        /// An instance of a picker the build lists, from `App.picker`.
        extension: extension.Selection,
    };

    pub const Check = struct {
        kind: Kind,
        /// Consecutive failed probes that eject an endpoint.
        fall: u8,
        /// Consecutive passing probes that restore it.
        rise: u8,
        /// One probe's whole budget.
        timeout_ms: u32,

        /// Tagged by the resolved check's own kind, so the two cannot
        /// come to name different sets.
        pub const Kind = union(config.Config.Cluster.Check.Kind) {
            /// A connect, and nothing sent.
            tcp,
            http: Http,
            /// `grpc.health.v1`, on an HTTP/2 cluster.
            grpc: Grpc,
            /// A build's own kind (#436), selected with `App.probe`: zoxy
            /// dials and holds the deadline, the type speaks the origin's
            /// protocol. Plaintext: refused on a TLS cluster.
            extension: extension.Selection,
        };

        pub const Http = struct {
            /// A canonical origin-form path.
            path: []const u8,
            /// The `Host` sent, or null for the endpoint's own literal.
            host: ?[]const u8 = null,
            /// The one status that passes.
            expect_status: u16,
        };

        pub const Grpc = struct {
            /// The service asked about; empty asks about the server.
            service: []const u8 = "",
        };
    };

    pub const PassiveEjection = struct {
        /// Consecutive failures the endpoint caused that eject it.
        fall: u8,
        /// How long an ejected endpoint stays out.
        recovery_ms: u32,
        /// The ceiling a repeated ejection's cooldown doubles toward
        /// (#394), or null to keep every cooldown at `recovery_ms`.
        recovery_ms_max: ?u32 = null,
    };

    pub const Retries = struct {
        /// Further endpoints one request may dial after a refused or
        /// unreachable first try (#181); HTTP/1.1 clusters only.
        count: u16 = 0,
        /// Retry dials the cluster may have in flight at once (#393), or
        /// null for no bound beyond `count`. Needs a `count`.
        budget: ?u16 = null,
    };

    pub const Tls = struct {
        /// The name every origin's certificate must prove; also the SNI.
        server_name: []const u8,
        /// The PEM bundle every origin's chain must reach.
        ca_pem: []const u8,
    };
};

/// Connection lifecycle deadlines, in milliseconds (§4, §6, §8).
pub const Timeouts = struct {
    /// One dial's budget.
    connect_ms: u32,
    /// How long a quiet connection lives, between requests or before its
    /// first byte. Must exceed `connect_ms`.
    idle_ms: u32,
    /// The budget for reading one request head once it has begun (#235):
    /// above `connect_ms`, and at most `idle_ms`.
    head_ms: u32,
    /// One tunnel's whole life (#180).
    tunnel_ms: u32,
    /// The pause between health-probe sweeps (§7).
    health_interval_ms: u32,
    /// One exchange's cap from routing to its last byte (§8); 0 is off.
    request_ms: u32 = 0,
    /// A connection's age cap (§6); 0 is off.
    max_lifetime_ms: u32 = 0,
    /// The drain's cap (§8); 0 waits for the last connection, leaving
    /// the bound to whoever sent the signal.
    drain_deadline_ms: u32 = 0,
    /// The serving loop's watchdog (#311), or null for none.
    loop_watchdog_ms: ?u32 = null,
};

/// Pool counts and buffer sizes (§5). Each member left null is sized by
/// zoxy's own rule for this config — the stock binary's, which the banner
/// prints — and each one stated is held to the same ceilings and
/// relations the rule obeys. Stated as a block even when every member is
/// null, so that leaving the sizing to zoxy is a decision the author
/// wrote down.
pub const Limits = struct {
    conn_slots: ?u32 = null,
    relay_buffers: ?u32 = null,
    upstream_slots: ?u32 = null,
    head_buffers: ?u32 = null,
    upstream_head_buffers: ?u32 = null,
    head_buffer_bytes: ?u32 = null,
    relay_buffer_bytes: ?u32 = null,
    tls_engines: ?u32 = null,
    tunnels: ?u32 = null,
    h2_connections: ?u32 = null,
    h2_streams: ?u32 = null,
    upstream_h2_connections: ?u32 = null,
    upstream_h2_streams: ?u32 = null,
    upstream_tls_sessions: ?u32 = null,
    cq_fill_eighths: ?u32 = null,
    access_log_buffer_bytes: ?u32 = null,
};

/// A named response body (#159), for an error page or a `respond` action
/// to send.
pub const Body = struct {
    /// Unique across the build, at most `body_name_bytes_max` bytes.
    name: []const u8,
    /// Sent as they are, at most `body_bytes_max`.
    bytes: []const u8,
    /// The `Content-Type` sent with them.
    content_type: []const u8,
};

/// A body for a status zoxy answers itself (#159). A status listed by no
/// page keeps its empty one.
pub const ErrorPage = struct {
    /// One of the statuses zoxy can answer itself (`shed.static_statuses`).
    status: u16,
    /// The name of one of the build's bodies.
    body: []const u8,
};

/// The admin listener (§8): the process counters in Prometheus text
/// format.
pub const Admin = struct {
    /// An IP and port; the plane takes no `unix:` path.
    bind: std.Io.net.IpAddress,
};

/// The access log (§8): one JSON line per HTTP exchange and per L4
/// connection, dropped and counted rather than blocking the loop when the
/// sink cannot keep up.
pub const AccessLog = struct {
    sink: Sink,
    /// Request headers each line records (#140), matched without regard
    /// to case and logged lowercase.
    request_headers: []const []const u8 = &.{},
    /// Response headers each line records (#140).
    response_headers: []const []const u8 = &.{},

    /// Standard output, or a file opened for append (never truncated, so
    /// copy-truncate rotation is safe).
    pub const Sink = config.Config.AccessLogSink;
};
