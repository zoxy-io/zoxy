//! The zoxy module root: re-exports every public component and aggregates all
//! module tests (the trailing `test` block — a new source file's tests only
//! run once it is imported there).
const std = @import("std");

/// The completion-based io_uring layer (docs/DESIGN.md "I/O architecture").
pub const io = @import("io/io.zig");

/// A SO_REUSEPORT TCP listener (docs/DESIGN.md §2).
pub const Listener = @import("net/listener.zig").Listener;

/// Hot-restart listener handoff over SCM_RIGHTS (docs/DESIGN.md §7 Phase 4).
pub const handoff = @import("net/handoff.zig");

/// Static limits (docs/TIGER_STYLE.md: "put a limit on everything").
pub const constants = @import("constants.zig");

/// Zero-copy HTTP/1.1 request/response parser + body framing (docs/DESIGN.md §5).
pub const h1 = @import("http/h1.zig");

/// Chunked transfer-coding decoder (finds message ends; relays verbatim).
pub const chunked = @import("http/chunked.zig");

/// Sans-io HTTP/2 frame codec (docs/DESIGN.md §7 Phase 5, slice 1).
pub const h2_frame = @import("http/h2_frame.zig");

/// HPACK header compression, strictly bounded (docs/DESIGN.md §7 Phase 5, slice 2).
pub const hpack = @import("http/hpack.zig");

/// Sans-io HTTP/2 server connection engine (docs/DESIGN.md §7 Phase 5, slice 3).
pub const h2 = @import("http/h2.zig");

/// Static proxy configuration (docs/DESIGN.md §7).
pub const config = @import("config.zig");

/// Request routing (host/path -> cluster).
pub const Router = @import("proxy/router.zig").Router;

/// P2C least-request load balancing.
pub const balancer = @import("proxy/balancer.zig");

/// Maglev consistent hashing (per-cluster lookup tables).
pub const maglev = @import("proxy/maglev.zig");

/// Per-worker resilience state: LB/breaker/outlier/retry accounting (§7 Phase 2).
pub const resilience = @import("proxy/resilience.zig");

/// Per-worker active health checking (TCP-connect probes, in-ring).
pub const HealthChecker = @import("proxy/health_check.zig").HealthChecker;

/// Per-worker idle upstream connection pool.
pub const UpstreamPool = @import("proxy/upstream_pool.zig").UpstreamPool;

/// The reverse-proxy data path (docs/DESIGN.md §5, §7).
pub const proxy = @import("net/proxy.zig");

/// Process-wide metrics: per-worker `Counters` shards, cache-line padded so
/// the data path never contends on a shared line (docs/DESIGN.md §7).
pub const Metrics = @import("obs/metrics.zig").Metrics;
pub const Counters = @import("obs/metrics.zig").Counters;
pub const Counter = @import("obs/metrics.zig").Counter;

/// Per-worker access log.
pub const AccessLog = @import("obs/access_log.zig").AccessLog;

/// Admin/metrics endpoint (blocking, on its own thread, off the data path).
pub const Admin = @import("obs/admin.zig").Admin;

/// Allocation guard for the zero-alloc acceptance gate (docs/DESIGN.md §4).
pub const guard = @import("mem/guard.zig");

/// Cache-line isolation for per-worker mutable state (metrics shards,
/// pool headers, access logs): neighbors in an array never share a line.
pub const cache_line = @import("mem/cache_line.zig");

/// TLS termination via OpenSSL FFI (docs/DESIGN.md §6, Phase 3).
pub const tls = @import("tls/openssl.zig");

/// Sans-io TLS terminator: SSL_CTX policy + per-connection BIO-pair channel.
pub const terminator = @import("tls/terminator.zig");

test {
    _ = io;
    _ = @import("io/test_io.zig");
    _ = @import("net/listener.zig");
    _ = handoff;
    _ = h1;
    _ = chunked;
    _ = h2_frame;
    _ = hpack;
    _ = h2;
    _ = config;
    _ = @import("proxy/router.zig");
    _ = balancer;
    _ = maglev;
    _ = resilience;
    _ = @import("proxy/health_check.zig");
    _ = @import("proxy/upstream_pool.zig");
    _ = @import("net/pool.zig");
    _ = proxy;
    _ = @import("obs/metrics.zig");
    _ = @import("obs/access_log.zig");
    _ = @import("obs/admin.zig");
    _ = guard;
    _ = cache_line;
    _ = tls;
    _ = terminator;
    _ = @import("tls/heap.zig");
    _ = @import("tls/kernel.zig");
    _ = @import("mem/futex_mutex.zig");
}
