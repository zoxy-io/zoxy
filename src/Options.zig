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
