//! What a build states about the proxy it runs (#417): the library's one
//! input. A custom build writes these in code; the stock binary's JSON is
//! a front-end that writes them from a file, and nothing past this type
//! knows which happened. The library validates them — every refusal the
//! stock loader makes, made here, once — and compiles them into the
//! `Config` the server runs.
//!
//! **Explicit by construction.** A field has no default if it decides
//! where traffic goes, when work is refused, or what is reserved:
//! deadlines, policies, caps a listener promises its clients. Optional
//! features default to off. The stock binary's JSON applies zoxy's stock
//! values where its keys are absent; a build writing options in code
//! states its own.
//!
//! **Bytes, not paths.** Certificates, CA bundles and bodies arrive as
//! bytes, so validating options reads no file: whoever builds them does,
//! from wherever they keep them.
//!
//! **Typed, not spelled.** Where JSON names a policy with a string and a
//! fork with a choice of keys, these carry an enum and a union, so the
//! refusals that only a spelling can earn stay in the JSON front-end.
//!
//! The split arrives one block at a time (#417's plan); the blocks below
//! are the ones the loader already resolves from options.

const std = @import("std");

const config = @import("config.zig");
const extension = @import("extension.zig");
const io = @import("io/io.zig");

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
