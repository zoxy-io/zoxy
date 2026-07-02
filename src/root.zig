//! The zoxy module root: re-exports every public component and aggregates all
//! module tests (the trailing `test` block — a new source file's tests only
//! run once it is imported there).
const std = @import("std");

/// The completion-based io_uring layer (docs/DESIGN.md "I/O architecture").
pub const io = @import("io/io.zig");

/// A SO_REUSEPORT TCP listener (docs/DESIGN.md §2).
pub const Listener = @import("net/listener.zig").Listener;

/// Static limits (docs/TIGER_STYLE.md: "put a limit on everything").
pub const constants = @import("constants.zig");

/// Zero-copy HTTP/1.1 request/response parser + body framing (docs/DESIGN.md §5).
pub const h1 = @import("http/h1.zig");

/// Chunked transfer-coding decoder (finds message ends; relays verbatim).
pub const chunked = @import("http/chunked.zig");

/// Static proxy configuration (docs/DESIGN.md §7).
pub const config = @import("config.zig");

/// Request routing (host/path -> cluster).
pub const Router = @import("proxy/router.zig").Router;

/// Round-robin load balancing.
pub const RoundRobin = @import("proxy/balancer.zig").RoundRobin;

/// The reverse-proxy data path (docs/DESIGN.md §5, §7).
pub const proxy = @import("net/proxy.zig");

/// Process-wide metrics counters (docs/DESIGN.md §7).
pub const Metrics = @import("obs/metrics.zig").Metrics;

/// Per-worker access log.
pub const AccessLog = @import("obs/access_log.zig").AccessLog;

/// Admin/metrics endpoint (blocking, on its own thread, off the data path).
pub const Admin = @import("obs/admin.zig").Admin;

/// Allocation guard for the zero-alloc acceptance gate (docs/DESIGN.md §4).
pub const guard = @import("mem/guard.zig");

test {
    _ = io;
    _ = @import("net/listener.zig");
    _ = h1;
    _ = chunked;
    _ = config;
    _ = @import("proxy/router.zig");
    _ = @import("proxy/balancer.zig");
    _ = @import("net/pool.zig");
    _ = proxy;
    _ = @import("obs/metrics.zig");
    _ = @import("obs/access_log.zig");
    _ = @import("obs/admin.zig");
    _ = guard;
}
